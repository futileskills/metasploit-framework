# encoding: utf-8
require 'msf/core'

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report
  include Msf::Exploit::Remote::Tcp

  def initialize(info = {})
    super(update_info(info,
      'Name'        => 'ESC/POS Network Printer Discovery (Buffered Output)',
      'Description' => %q{
        Identifies network printers likely ESC/POS-compatible (Epson TM series, Star Micronics, BIXOLON)
        by checking TCP/9100 and optionally sending a safe ESC/POS status query.
        Collects likely printer IPs and prints them all at the end.
      },
      'Author'      => ['FutileSkills'],
      'License'     => MSF_LICENSE
    ))

    register_options(
      [
        Opt::RHOSTS,
        Opt::RPORT(9100),
        OptInt.new('TIMEOUT', [true, 'TCP read timeout (ms)', 1000]),
        OptBool.new('ACTIVE_CHECK', [true, 'Send safe ESC/POS status (DLE EOT 1)', true]),
      ]
    )

    @found_printers = []
  end

  DLE_EOT1 = "\x10\x04\x01".b

  def run_host(ip)
    likely = false

    begin
      connect(true)
      if datastore['ACTIVE_CHECK']
        sock.put(DLE_EOT1)
        sock.flush
        resp = sock.get_once(datastore['TIMEOUT'].to_i / 1000.0)
        likely = true if resp && !resp.empty?
      else
        likely = true  # TCP/9100 open is enough
      end
    rescue ::Rex::ConnectionError
      likely = false
    ensure
      disconnect rescue nil
    end

    if likely
      @found_printers << ip

      # Report to Metasploit database
      store_service(host: ip, port: rport, proto: 'tcp', name: 'printer-raw-9100')
      report_note(
        host: ip,
        type: 'printer.escpos.discovery',
        data: { escpos_candidate: true },
        update: true
      )
    end
  end

  # This is called automatically by the scanner mixin after all hosts are scanned
  def run_completed
    return if @found_printers.empty?

    print_good("\n=== Likely ESC/POS Printers Found ===")
    @found_printers.uniq.each do |ip|
      puts "[ESC/POS] #{ip}"
    end
    print_good("=== End of Scan ===\n")
  end
end
