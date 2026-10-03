import {
  withBesa,
  BesaRuntimeError,
  canonicalize,
  hashRequest,
  type ActionEnvelopeV1,
  type BesaExecutionResult,
  type BesaRuntimeConfig,
} from "@dorigjo/besa";

export interface HttpRequestLike {
  method?: string;
  url?: string;
  body?: unknown;
}

function freezeRequest(value: unknown): void {
  if (value === null || typeof value !== "object") return;
  for (const child of Object.values(value)) freezeRequest(child);
  Object.freeze(value);
}

export function protectHttpHandler<TRequest extends HttpRequestLike, TResult>(
  config: BesaRuntimeConfig,
  actionForRequest: (request: TRequest) => ActionEnvelopeV1 | Promise<ActionEnvelopeV1>,
  execute: (request: TRequest) => TResult | Promise<TResult>,
): (request: TRequest) => Promise<BesaExecutionResult<TResult>> {
  return async (requestValue) => {
    // Pass a plain request DTO, not the framework's live socket/request object.
    const request = JSON.parse(canonicalize(requestValue)) as TRequest;
    freezeRequest(request);
    const action = await actionForRequest(request);
    if (action.requestHash !== hashRequest(request.body)) {
      throw new BesaRuntimeError("ACTION_REQUEST_MISMATCH",
        "Besa action requestHash does not match the HTTP body");
    }
    return withBesa(config, () => execute(request))(action);
  };
}
