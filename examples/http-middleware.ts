import {
  withBesa,
  type ActionEnvelopeV1,
  type BesaExecutionResult,
  type BesaRuntimeConfig,
} from "@dorigjo/besa";

export interface HttpRequestLike {
  method?: string;
  url?: string;
  body?: unknown;
}

export function protectHttpHandler<TRequest extends HttpRequestLike, TResult>(
  config: BesaRuntimeConfig,
  actionForRequest: (request: TRequest) => ActionEnvelopeV1 | Promise<ActionEnvelopeV1>,
  execute: (request: TRequest) => TResult | Promise<TResult>,
): (request: TRequest) => Promise<BesaExecutionResult<TResult>> {
  return async (request) => {
    const action = await actionForRequest(request);
    return withBesa(config, () => execute(request))(action);
  };
}
