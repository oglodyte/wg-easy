import { FetchError } from 'ofetch';

type RevertFn<T> = (success: boolean, data: T | undefined) => Promise<void>;

type SubmitOpts<T> = {
  revert: RevertFn<T>;
  successMsg?: string;
  noSuccessToast?: boolean;
};

type Body = Record<string, unknown> | null | undefined;

// Infer the concrete callback before unwrapping its result. Contextual Promise
// inference expands Nitro route unions beyond TypeScript's recursion limit.
export function useSubmit<Fetcher extends (data: Body) => unknown>(
  fetcher: Fetcher,
  opts: SubmitOpts<Awaited<ReturnType<Fetcher>>>
) {
  const toast = useToast();

  return async (data: Body) => {
    try {
      const res = await fetcher(data);

      if (!opts.noSuccessToast) {
        toast.showToast({
          type: 'success',
          message: opts.successMsg,
        });
      }

      await opts.revert(true, res as Awaited<ReturnType<Fetcher>>);
    } catch (e) {
      if (e instanceof FetchError) {
        toast.showToast({
          type: 'error',
          message: e.data.message,
        });
      } else if (e instanceof Error) {
        toast.showToast({
          type: 'error',
          message: e.message,
        });
      } else {
        console.error(e);
      }
      await opts.revert(false, undefined);
    }
  };
}
