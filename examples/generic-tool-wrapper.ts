import {
  withBesa,
  type ActionEnvelopeV1,
  type BesaRuntimeConfig,
} from "@dorigjo/besa";

export function protectTool<TResult>(
  config: BesaRuntimeConfig,
  execute: (action: ActionEnvelopeV1) => TResult | Promise<TResult>,
) {
  const admitted = withBesa(config, execute);

  return async (action: ActionEnvelopeV1) => {
    const { result, evidence } = await admitted(action);
    return { result, evidence };
  };
}
