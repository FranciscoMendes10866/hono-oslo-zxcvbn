import type { Static, TObject } from "@sinclair/typebox";
import { TypeCompiler, type ValueError } from "@sinclair/typebox/compiler";

class ValidationError extends Error {
  public readonly valueError: Partial<ValueError>;
  constructor(valueError?: Partial<ValueError>) {
    super();
    this.name = "ValidationError";
    this.valueError = {
      ...valueError,
      path: valueError?.path || "",
      message: valueError?.message || "Unknown validation error",
    };
  }
}

export function validatorFactory<T extends TObject>(
  schema: T,
): {
  parse: (data: unknown) => Static<T>;
  isValid: (data: unknown) => boolean;
} {
  const compiled = TypeCompiler.Compile(schema);
  return {
    parse: (data: unknown): Static<T> => {
      const clone = structuredClone(data);
      if (compiled.Check(clone)) return clone as Static<T>;
      throw new ValidationError(compiled.Errors(clone).First());
    },
    isValid: (data: unknown): boolean => {
      return compiled.Check(structuredClone(data));
    },
  };
}
