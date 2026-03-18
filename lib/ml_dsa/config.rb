# frozen_string_literal: true

module MlDsa
  # Thread-safe configuration holder for instrumentation subscribers
  # and pluggable RNG.  Each Ractor or test context can have its own
  # Config instance.
  #
  # @example Custom config for testing
  #   cfg = MlDsa::Config.new
  #   cfg.random_source = proc { |n| "\x42" * n }
  #   pk, sk = MlDsa.keygen(MlDsa::ML_DSA_65, config: cfg)
  class Config
    def initialize
      @subscribers = []
      @mutex = Mutex.new
      @random_source = nil
    end

    # Subscribe to instrumentation events. The block receives a frozen Hash
    # with keys +:operation+, +:param_set+, +:count+, and +:duration_ns+.
    #
    # @yield [Hash] event payload
    # @return [Proc] the subscriber (pass to {.unsubscribe} to remove)
    def subscribe(&block)
      raise ArgumentError, "subscribe requires a block" unless block
      @mutex.synchronize { @subscribers << block }
      block
    end

    # Remove a previously registered subscriber.
    # @param subscriber [Proc] the block returned by {#subscribe}
    # @return [Proc, nil] the removed subscriber, or nil if not found
    def unsubscribe(subscriber)
      @mutex.synchronize { @subscribers.delete(subscriber) }
    end

    # @return [Proc, nil] the current random source, or nil for OS CSPRNG
    attr_reader :random_source

    # Set a custom random source. The proc must accept a single Integer
    # argument (byte count) and return a binary String of that length.
    #
    # @param source [Proc, nil]
    def random_source=(source)
      if source && !source.respond_to?(:call)
        raise TypeError, "random_source must respond to :call or be nil"
      end
      @random_source = source
    end

    # @api private — fire event to all subscribers
    def notify(operation, param_set, count, duration_ns)
      # In non-main Ractors, skip instrumentation to avoid isolation errors
      if defined?(Ractor) && Ractor.respond_to?(:main?) && !Ractor.main?
        return nil
      end
      subs = @mutex.synchronize { @subscribers.dup }
      return if subs.empty?
      event = {
        operation: operation,
        param_set: param_set,
        count: count,
        duration_ns: duration_ns
      }.freeze
      subs.each { |s| s.call(event) }
      nil
    end
  end
end
