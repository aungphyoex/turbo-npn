import { Injectable } from '@nestjs/common';
import { InjectEntityManager } from '@nestjs/typeorm';
import { EntityManager } from 'typeorm';

@Injectable()
export class TransactionService {
  constructor(
    @InjectEntityManager() private readonly entityManager: EntityManager,
  ) {}

  /**
   * Runs a function inside a transaction using TypeORM's transaction manager.
   * Automatically commits or rolls back on error.
   *
   * @param fn A function that receives the transaction-aware EntityManager
   */
  async runInTransaction<T>(
    fn: (manager: EntityManager) => Promise<T>,
  ): Promise<T> {
    return this.entityManager.transaction(async (transactionManager) => {
      return fn(transactionManager);
    });
  }
}
