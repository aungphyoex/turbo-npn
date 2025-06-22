import { BadRequestException, PipeTransform } from '@nestjs/common';
import { ZodSchema, z } from 'zod';

/**
 * Pipe for validating and transforming incoming data using a Zod schema.
 *
 * Validates the provided value against the given Zod schema.
 * Throws a BadRequestException if validation fails, including field errors.
 */
export class ZodValidatorPipe implements PipeTransform {
  /**
   * Creates an instance of ZodValidatorPipe.
   *
   * @param {ZodSchema} schema - The Zod schema to validate against.
   */
  constructor(private schema: ZodSchema) {}

  /**
   * Transforms and validates the incoming value.
   *
   * @param {unknown} value - The value to validate.
   * @returns {z.infer<typeof this.schema>} The validated and parsed data.
   * @throws {BadRequestException} If validation fails.
   */
  transform(value: unknown): z.infer<typeof this.schema> {
    const validateFields = this.schema.safeParse(value);
    if (!validateFields.success)
      throw new BadRequestException({
        errors: validateFields.error.flatten().fieldErrors,
      });
    return validateFields.data;
  }
}
