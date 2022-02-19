export class Events {
  private handlers: Map<string, Set<Function>> = new Map();

  constructor() {
  }

  addListener(event: string, listener: (...args: any[]) => void): this {
    this.getHandlers(event)
      .add(listener);

    return this;
  }

  emit(event: string, ...args: any[]): boolean {
    const handlers = this.getHandlers(event);

    if (handlers.size === 0) {
      return false;
    }

    handlers.forEach(handler =>
      setTimeout(
        () => Reflect.apply(handler, this, args),
        0
      )
    );

    return true;
  }

  eventNames(): string[] {
    return [...this.handlers.keys()];
  }

  listenerCount(event: string) {
    return this.getHandlers(event).size;
  }

  listeners(event: string): Function[] {
    return [
      ...this.getHandlers(event)
        .values()
    ];
  }

  off(event: string, listener: (...args: any[]) => void): this {
    return this.removeListener(event, listener);
  }

  on(event: string, listener: (...args: any[]) => void): this {
    return this.addListener(event, listener);
  }

  once(event: string, listener: (...args: any[]) => void): this {

    const listenerRemove = () => {
      this.removeListener(event, listener);
      this.removeListener(event, listenerRemove);
    };

    this.addListener(event, listener);
    this.addListener(event, listenerRemove);

    return this;
  }


  removeAllListeners(event: string) {
    this.handlers.delete(event);

    return this;
  }

  removeListener(event: string, listener: (...args: any[]) => void): this {
    const handlers = this.getHandlers(event);

    handlers.delete(listener);

    if (handlers.size === 0) {
      this.handlers.delete(event);
    }

    return this;
  }


  private getHandlers(event: string) {
    return this.handlers.get(event) ??
      this.handlers.set(event, new Set())
        .get(event)!;
  }
}
