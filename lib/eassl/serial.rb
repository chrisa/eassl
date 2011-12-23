require 'eassl'
module EaSSL
  # Author::    Chris Andrews  (mailto:chris@nodnol.org)
  # Copyright:: Copyright (c) 2011 Chris Andrews
  # License::   Distributes under the same terms as Ruby
  class Serial
    attr_reader :next
    def initialize(options = {})
      @next = options[:next]
      @path = options[:path]
    end

    def self.load(serial_file_path)
      hex_string = (File.read(serial_file_path))
      self.new(:next => Integer("0x#{hex_string}"), :path => serial_file_path)
    end

    def save!
      if @path
        hex_string = sprintf("%04X", @next)
        File.open(@path, 'w') do |io|
          io.write "#{hex_string}\n"
        end
      end
    end

    def issue_serial
      @next = @next + 1
      @next - 1
    end
  end
end

