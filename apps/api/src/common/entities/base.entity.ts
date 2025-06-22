import {
  CreateDateColumn,
  Entity,
  PrimaryGeneratedColumn,
  UpdateDateColumn,
} from 'typeorm';

/**
 * Abstract base entity class providing common fields for all entities.
 *
 * @property {string} id - Unique identifier generated as a UUID.
 * @property {Date} createdAt - Timestamp when the entity was created.
 * @property {Date} updatedAt - Timestamp when the entity was last updated.
 */
@Entity()
export abstract class Base {
  /**
   * Unique identifier generated as a UUID.
   * @type {string}
   */
  @PrimaryGeneratedColumn('uuid')
  id: string;

  /**
   * Timestamp when the entity was created.
   * @type {Date}
   */
  @CreateDateColumn()
  createdAt: Date;

  /**
   * Timestamp when the entity was last updated.
   * @type {Date}
   */
  @UpdateDateColumn()
  updatedAt: Date;
}
