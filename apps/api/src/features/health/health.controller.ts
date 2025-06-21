import { Public } from '@/common/decorators';
import { Controller, Get } from '@nestjs/common';
import {
  DiskHealthIndicator,
  HealthCheck,
  HealthCheckService,
  HttpHealthIndicator,
  MemoryHealthIndicator,
  TypeOrmHealthIndicator,
} from '@nestjs/terminus';

/**
 * Controller for health checks of various system components.
 *
 * Provides endpoints to check the health of the database, external HTTP service, disk storage, and memory usage.
 */
@Controller('health')
export class HealthController {
  /**
   * Creates an instance of HealthController.
   *
   * @param health - Service to perform health checks.
   * @param http - HTTP health indicator for external service checks.
   * @param db - Database health indicator.
   * @param disk - Disk storage health indicator.
   * @param memory - Memory usage health indicator.
   */
  constructor(
    private health: HealthCheckService,
    private http: HttpHealthIndicator,
    private db: TypeOrmHealthIndicator,
    private readonly disk: DiskHealthIndicator,
    private readonly memory: MemoryHealthIndicator,
  ) {}

  /**
   * Checks the health of the database connection.
   *
   * @returns The result of the database ping health check.
   */
  @Public()
  @Get('database')
  @HealthCheck()
  checkDatabase() {
    return this.health.check([() => this.db.pingCheck('database')]);
  }

  /**
   * Checks the health of an external HTTP service.
   *
   * @returns The result of the HTTP ping health check.
   */
  @Public()
  @Get()
  @HealthCheck()
  check() {
    return this.health.check([
      () =>
        this.http.pingCheck('aung pyae phyo', 'https://www.aungpyaephyo.com'),
    ]);
  }

  /**
   * Checks the health of the disk storage.
   *
   * @returns The result of the disk storage health check.
   */
  @Public()
  @Get('disk')
  @HealthCheck()
  checkDisk() {
    return this.health.check([
      () =>
        this.disk.checkStorage('storage', { path: '/', thresholdPercent: 0.5 }),
    ]);
  }

  /**
   * Checks the heap memory usage.
   *
   * @returns The result of the memory heap health check.
   */
  @Public()
  @Get('memory')
  @HealthCheck()
  checkMemory() {
    return this.health.check([
      () => this.memory.checkHeap('memory_heap', 150 * 1024 * 1024),
    ]);
  }
}
