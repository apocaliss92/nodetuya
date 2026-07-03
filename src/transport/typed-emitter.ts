import { EventEmitter } from 'node:events';

export class TypedEmitter<TEvents extends Record<string, unknown>> {
  private readonly emitter = new EventEmitter();
  on<K extends keyof TEvents & string>(event: K, listener: (payload: TEvents[K]) => void): this {
    this.emitter.on(event, listener as (p: unknown) => void);
    return this;
  }
  off<K extends keyof TEvents & string>(event: K, listener: (payload: TEvents[K]) => void): this {
    this.emitter.off(event, listener as (p: unknown) => void);
    return this;
  }
  once<K extends keyof TEvents & string>(event: K, listener: (payload: TEvents[K]) => void): this {
    this.emitter.once(event, listener as (p: unknown) => void);
    return this;
  }
  emit<K extends keyof TEvents & string>(event: K, payload: TEvents[K]): boolean {
    return this.emitter.emit(event, payload);
  }
  removeAllListeners(): void {
    this.emitter.removeAllListeners();
  }
}
