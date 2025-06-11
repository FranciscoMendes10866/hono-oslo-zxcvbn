import { Type as T } from "@sinclair/typebox";

import { validatorFactory } from "./utils/validator";

export const signUpBodySchema = validatorFactory(
  T.Object({
    username: T.Optional(T.String({ minLength: 6, maxLength: 48 })),
    email: T.String({ format: "email" }),
    password: T.String({ minLength: 8, maxLength: 64 }),
    confirmPassword: T.String({ minLength: 8, maxLength: 64 }),
  }),
);

export const requestEmailVerificationParamsSchema = validatorFactory(
  T.Object({
    userId: T.String({ format: "uuid" }),
  }),
);

export const requestEmailVerificationQuerySchema = validatorFactory(
  T.Object({
    code: T.String(),
  }),
);

export const requestEmailUpdateBodySchema = validatorFactory(
  T.Object({
    newEmail: T.String({ format: "email" }),
  }),
);

export const signInBodySchema = validatorFactory(
  T.Object({
    email: T.String({ format: "email" }),
    password: T.String({ minLength: 8, maxLength: 64 }),
  }),
);

export const requestResetPasswordBodySchema = validatorFactory(
  T.Object({
    email: T.String({ format: "email" }),
  }),
);

export const verifyResetPasswordParamsSchema = validatorFactory(
  T.Object({
    code: T.String(),
  }),
);

export const resetPasswordBodySchema = validatorFactory(
  T.Object({
    password: T.String({ minLength: 8, maxLength: 64 }),
    confirmPassword: T.String({ minLength: 8, maxLength: 64 }),
  }),
);
