import {
  sanitizeBrowserUrl,
  type InspectWebPageInput,
} from "../domain/browserObservation.js";
import { parseRecordedTransportUrl } from "../domain/recordedTransportUrl.js";
import {
  browserCssVariableItemSchema,
  type BrowserCssVariableItem,
  type BrowserCssVariables,
} from "../domain/browserObservationSchemas.js";
import { compareUnicodeCodePoints } from "../domain/unicodeCodePointOrder.js";
import { CdpCommandRejection } from "./CdpCommandRejection.js";
import {
  cdpStringValue,
  numberValue,
  recordValue,
  recordsValue,
} from "./CdpCaptureValues.js";
import type { CdpConnection } from "./CdpConnection.js";
import { optionalCdpCommand } from "./CdpOptionalCommand.js";

const MAX_RETAINED_CSS_VARIABLES = 250;
const MAX_INTAKE_CSS_VARIABLES = 2000;
const MAX_REJECTED_PREVIEWS = 3;
const MAX_PREVIEW_NAME_LENGTH = 64;

const MAX_CSS_VALUE_LENGTH = 512;
const CSS_URL_DOUBLE_QUOTED_PATTERN = /(url\(\s*")([^"\r\n]+)("\s*\))/gi;
const CSS_URL_SINGLE_QUOTED_PATTERN = /(url\(\s*')([^'\r\n]+)('\s*\))/gi;
const CSS_URL_UNQUOTED_PATTERN = /(url\(\s*)([^"'\s()\r\n]+)(\s*\))/gi;

const sanitizeDiagnosticPreview = (text: string): string =>
  text.replace(/[\u0000-\u001F\u007F-\u009F\u202A-\u202E\u2066-\u2069]/gu, "");

const redactCssUrl = (
  rawUrl: string,
): { readonly url: string; readonly redacted: boolean } => {
  const { credentials } = parseRecordedTransportUrl(rawUrl);
  if (credentials !== null && typeof credentials === "object") {
    return {
      url: `${rawUrl.slice(0, credentials.start)}${rawUrl.slice(credentials.end)}`,
      redacted: true,
    };
  }
  const sanitized = sanitizeBrowserUrl(rawUrl);
  if (sanitized.redacted) {
    return { url: sanitized.url, redacted: true };
  }
  return { url: rawUrl, redacted: false };
};

const redactUrlPattern = (text: string, pattern: RegExp): string =>
  text.replace(
    pattern,
    (fullMatch, prefix: string, rawUrl: string, suffix: string) => {
      try {
        const sanitized = redactCssUrl(rawUrl);
        if (!sanitized.redacted) return fullMatch;
        return `${prefix}${sanitized.url}${suffix}`;
      } catch {
        return fullMatch;
      }
    },
  );

export const redactCssUrlCredentials = (value: string): string => {
  if (
    value.length > MAX_CSS_VALUE_LENGTH ||
    !value.toLowerCase().includes("url(")
  ) {
    return value;
  }
  const step1 = redactUrlPattern(value, CSS_URL_DOUBLE_QUOTED_PATTERN);
  const step2 = redactUrlPattern(step1, CSS_URL_SINGLE_QUOTED_PATTERN);
  return redactUrlPattern(step2, CSS_URL_UNQUOTED_PATTERN);
};

const emptyCssVariables = (
  status: BrowserCssVariables["status"],
): BrowserCssVariables => ({
  status,
  origin_scope: "same_origin",
  total: 0,
  retained_count: 0,
  items: [],
});

const safeCdpCommand = async (
  context: {
    readonly connection: CdpConnection;
    readonly sessionId: string | undefined;
    readonly signal?: AbortSignal;
  },
  method: string,
  parameters: Readonly<Record<string, unknown>>,
  limitations: string[],
): Promise<unknown | undefined> => {
  try {
    return await optionalCdpCommand(context, method, parameters, limitations);
  } catch (cause: unknown) {
    if (cause instanceof CdpCommandRejection && cause.code === -32000) {
      limitations.push(
        `${method} failed (CDP error -32000): ${cause.reportedMessage ?? "target node detached or unavailable"}.`,
      );
      return undefined;
    }
    throw cause;
  }
};

/**
 * Passively extract declared and computed CSS custom properties (variables)
 * for the root document element of an authorized page target.
 */
export const captureCssVariables = async (
  context: {
    readonly connection: CdpConnection;
    readonly sessionId: string | undefined;
    readonly input: InspectWebPageInput;
    readonly signal?: AbortSignal;
    readonly events?: {
      readonly completeness: {
        readonly exclude: (
          section: "css_variables",
          reason: "invalid_protocol_value",
          count: number | null,
        ) => void;
      };
    };
  },
  limitations: string[],
): Promise<BrowserCssVariables> => {
  if (!context.input.include_css_variables) {
    return emptyCssVariables("not_approved");
  }

  const doc = await safeCdpCommand(
    context,
    "DOM.getDocument",
    { depth: 1 },
    limitations,
  );
  if (doc === undefined) {
    return emptyCssVariables("unavailable");
  }

  const rootRecord = recordValue(recordValue(doc)?.root);
  if (rootRecord === undefined) {
    context.events?.completeness.exclude(
      "css_variables",
      "invalid_protocol_value",
      1,
    );
    limitations.push("DOM.getDocument response omitted valid root node.");
    return emptyCssVariables("unavailable");
  }

  const children = recordsValue(rootRecord.children);
  const elementChild = children.find((c) => numberValue(c.nodeType) === 1);
  const targetNodeId =
    numberValue(elementChild?.nodeId) ?? numberValue(rootRecord.nodeId);

  if (targetNodeId === undefined || targetNodeId <= 0) {
    context.events?.completeness.exclude(
      "css_variables",
      "invalid_protocol_value",
      1,
    );
    limitations.push(
      "DOM.getDocument response root node omitted valid numeric nodeId.",
    );
    return emptyCssVariables("unavailable");
  }

  const enabled = await safeCdpCommand(context, "CSS.enable", {}, limitations);
  if (enabled === undefined) {
    return emptyCssVariables("unavailable");
  }

  let computedResult: unknown;
  try {
    computedResult = await safeCdpCommand(
      context,
      "CSS.getComputedStyleForNode",
      { nodeId: targetNodeId },
      limitations,
    );
  } finally {
    await safeCdpCommand(context, "CSS.disable", {}, limitations).catch(
      () => undefined,
    );
  }

  if (computedResult === undefined) {
    return emptyCssVariables("unavailable");
  }

  const computedStyleVal = recordValue(computedResult)?.computedStyle;
  if (!Array.isArray(computedStyleVal)) {
    context.events?.completeness.exclude(
      "css_variables",
      "invalid_protocol_value",
      1,
    );
    limitations.push(
      "CSS.getComputedStyleForNode response omitted valid computedStyle property list.",
    );
    return emptyCssVariables("unavailable");
  }

  const validItems: BrowserCssVariableItem[] = [];
  let totalObserved = 0;
  let rejectedCount = 0;
  let malformedProtocolEntries = 0;
  const rejectedPreviews: string[] = [];

  for (const entry of computedStyleVal) {
    const prop = recordValue(entry);
    if (prop === undefined) {
      malformedProtocolEntries += 1;
      continue;
    }
    const name = cdpStringValue(prop.name);
    if (name === undefined) {
      malformedProtocolEntries += 1;
      continue;
    }
    if (!name.startsWith("--")) {
      continue;
    }
    const rawValue = cdpStringValue(prop.value);
    if (rawValue === undefined) {
      malformedProtocolEntries += 1;
      totalObserved += 1;
      rejectedCount += 1;
      if (rejectedPreviews.length < MAX_REJECTED_PREVIEWS) {
        const sanitizedName = sanitizeDiagnosticPreview(name);
        const truncatedName =
          sanitizedName.length > MAX_PREVIEW_NAME_LENGTH
            ? `${sanitizedName.slice(0, MAX_PREVIEW_NAME_LENGTH - 3)}...`
            : sanitizedName;
        rejectedPreviews.push(
          `${truncatedName} (missing or invalid protocol string value)`,
        );
      }
      continue;
    }

    totalObserved += 1;

    const sanitizedValue =
      rawValue.length > MAX_CSS_VALUE_LENGTH
        ? rawValue
        : redactCssUrlCredentials(rawValue);
    const redacted = sanitizedValue !== rawValue;
    const parsed = browserCssVariableItemSchema.safeParse({
      name,
      value: sanitizedValue,
      redacted,
    });
    if (parsed.success) {
      if (validItems.length < MAX_INTAKE_CSS_VARIABLES) {
        validItems.push(parsed.data);
      }
    } else {
      rejectedCount += 1;
      if (rejectedPreviews.length < MAX_REJECTED_PREVIEWS) {
        const sanitizedName = sanitizeDiagnosticPreview(name);
        const truncatedName =
          sanitizedName.length > MAX_PREVIEW_NAME_LENGTH
            ? `${sanitizedName.slice(0, MAX_PREVIEW_NAME_LENGTH - 3)}...`
            : sanitizedName;
        const issue =
          parsed.error.issues[0]?.message ?? "invalid token format or size";
        rejectedPreviews.push(`${truncatedName} (${issue})`);
      }
    }
  }

  if (malformedProtocolEntries > 0) {
    context.events?.completeness.exclude(
      "css_variables",
      "invalid_protocol_value",
      malformedProtocolEntries,
    );
    limitations.push(
      `CSS.getComputedStyleForNode response contained ${String(malformedProtocolEntries)} malformed property ${malformedProtocolEntries === 1 ? "entry" : "entries"} (missing or invalid protocol values).`,
    );
  }

  if (rejectedCount > 0) {
    const preview = rejectedPreviews.join(", ");
    const remaining =
      rejectedCount > rejectedPreviews.length
        ? ` and ${String(rejectedCount - rejectedPreviews.length)} more`
        : "";
    limitations.push(
      `${String(rejectedCount)} root CSS custom ${rejectedCount === 1 ? "property was" : "properties were"} rejected: ${preview}${remaining}.`,
    );
  }

  validItems.sort((left, right) =>
    compareUnicodeCodePoints(left.name, right.name),
  );

  const total = totalObserved;
  const items = validItems.slice(0, MAX_RETAINED_CSS_VARIABLES);
  const redactedCount = items.filter((item) => item.redacted).length;
  if (redactedCount > 0) {
    limitations.push(
      `${String(redactedCount)} root CSS custom ${redactedCount === 1 ? "property value had transport credentials redacted" : "property values had transport credentials redacted"}.`,
    );
  }

  const status: BrowserCssVariables["status"] =
    malformedProtocolEntries > 0 && items.length === 0
      ? "unavailable"
      : total > items.length || malformedProtocolEntries > 0
        ? "truncated"
        : "included";

  if (total > MAX_RETAINED_CSS_VARIABLES) {
    limitations.push(
      `CSS custom properties were truncated to ${String(MAX_RETAINED_CSS_VARIABLES)} items (${String(total)} were observed on the root element).`,
    );
  }

  return {
    status,
    origin_scope: "same_origin",
    total,
    retained_count: items.length,
    items,
  };
};
