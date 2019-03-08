#!/usr/bin/env ruby

require 'discordrb'
require 'json'
require 'mechanize'
require 'creek'
require 'base64'
require 'csv'
require 'blockchain'
require 'droplet_kit'
require 'uptimerobot'
require 'tempfile'
require './utils/dnsdumpster.rb'
require './utils/greynoise.rb'
require './utils/littleshodan.rb'
require './utils/whois.rb'
require './utils/ipinfo.rb'
require './utils/hashcracker.rb'
require './utils/hashfactory.rb'
require './utils/linkedin.rb'
require './utils/impy/impy.rb'
require './utils/exploitdb.rb'
require './utils/hibp.rb'
require './utils/shellbox.rb'
require './utils/chattable.rb'
require './utils/sploitus.rb'

tokens = {}
perm = {}
brain = {}


if File.file?("tokens.json")
    begin
        tokens = JSON.parse(File.open("tokens.json").read())
    rescue
        puts "tokens.json is either invalid or empty!"
    end
else
    puts "tokens.json does not exist."
end

# Class initializations
ipinfo = IPInfo.new(tokens["shodan"])
shodan = LittleShodan.new(tokens["shodan"])
dnsdumpster = DNSDumpster.new()
whois = ReverseWhois.new()
hashcracker = HashCracker.new()
linkedin = Linkedin.new()
hashfactory = HashFactory.new()
exploitdb = ExploitDB.new(exploit_csv="utils/exploitdb/files_exploits.csv", shellcode_csv="utils/exploitdb/files_shellcodes.csv")
explorer = Blockchain::BlockExplorer.new
hibp = HaveIBeenPwned.new()
ct = ChatTable.new()
# status = 0x00Status.new()
shellbox = ShellBox.new(tokens["digitalocean"], tokens["domain"], tokens["email"])
uptimerobot = UptimeRobot::Client.new(api_key: tokens["uptime_robot"])
sploitus = Sploitus.new()
bot = Discordrb::Commands::CommandBot.new token: tokens["discord_client_token"], prefix: 'karen, '

if File.file?("perms.json")
    begin
        perms = JSON.parse(File.open("perms.json").read())
        perms["roles"].each do |name, data|
            bot.set_role_permission(data["id"], data["level"])
        end
    rescue => e
        puts "perms.json is either invalid or empty! #{e.to_s}"
    end
end

if File.file?("brain.json")
    begin
        brain = JSON.parse(File.open("brain.json").read())
    rescue => e
        puts "brain.json is either invalid or empty! #{e.to_s}"
    end
end

bot.message() do |event|
  if event.server.name == "0x00sec VIP"
    words = event.content.split(" ")
    words.each do |word|
        if word[0..6] == "http://"
            bot.send_message(547503178162110476, event.user.name + ": " + word)
        elsif word[0..7] == "https://"
            bot.send_message(547503178162110476, event.user.name + ": " + word)
        end
    end
  end
  # The `respond` method returns a `Message` object, which is stored in a variable `m`. The `edit` method is then called
  # to edit the message with the time difference between when the event was received and after the message was sent.
end

# Help menu
bot.command(:help) do |event|
  event << "**Passive Recon**```"
  event << "karen, scanip  <domain>               : Get IP info/passive scan with shodan/greynoise"
  event << "karen, getsubs <domain>               : Get Subdomains from DNSDumpster"
  event << "karen, getmap* <domain>               : Get Subdomains map from DNSDumpster"
  event << "karen, getrefs <ip>                   : Get censys/shodan references"
  event << "karen, shodancount <query>            : Get Shodan count"
  event << "karen, revwhois <name/query>          : Get Reversewhois results"
  event << "karen, companylinkedin <company name> : Try and find company linkedin page."
  event << "karen, pwned <email>                  : Query HaveIBeenPwned for breaches"
  event << "```"

  event << "** Crypto ** ```"
  event << "karen, prettyjson <json>              : Pretty Print JSON"
  event << "karen, b64encode <text>               : Encode to Base64"
  event << "karen, b64decode <base64>             : Decode Base64"
  event << "karen, crackhash <hash>               : Crack hash"
  event << "karen, hashlookup <somehash>          : Identify a hash"
  event << "karen, hash sha256 <text>             : Identify a hash"
  event << "karen, btclookup <btcaddress>         : Get information from a BTC address"
  event << "```"

  event << "** Shells and Exploits**```"
  event << "karen, gimmeshell <ip:port>           : Generate a reverse shell with ELF + Base64. Restricted command."
  event << "karen, exploits <query>               : Search ExploitDB for exploits"
  event << "karen, shellcodes <query>             : Search ExploitDB for shellcodes"
  event << "karen, getfile <id>                   : Get file from exploitdb, using its ID"
  event << "```"

  event << "** 0x00sec **"
  event << "```"
  event << "karen, status"
  event << "```"
end

# Example command
## You can copy this entire block, change the command name, and implement new code things
## with error checking easily!
bot.command(:example_command) do |event, optional_var|
    output = ""
    begin
        #                         #
        # do something fun!       #
        # Your code here          #
        #                         #
        output += "Hello world! :joy: #{optional_var}\n"
        # Anything you put in output, is displayed
        # You need to separate newlines, you can also add emojis!
    rescue => e
        # Catch errors and output error
        output += "Something went wrong here. #{e.to_s}"
    else
        # Truncate as Discord only allows 2000 chars
        if output.length >= 1998
            output = output[0..1985]
            output += "(truncated)"
        else
            # If all went well, return it! (this prints it to the display)
            return output
        end
    end
end

# Get OSINT on IP
bot.command(:scanip) do |event, ip|
    output = ""
    begin
        if ip != nil
            ip.gsub!(" ", "")
        end
        if ip != nil and ip != ""
            data = ipinfo.scan(ip)
            output += "**IP:** #{data["ip"]}\n"
            output += "**Ports:** #{data["ports"]}\n"
            output += "**City:** #{data["city"]} **Region:** #{data["region"]} **Coordinates:** #{data["loc"]} **Country:** #{data["country"]}  :flag_#{data["country"].downcase}:\n"
            output += "**Organisation:** #{data["org"]}\n"
            output += "**Reported:** #{data["ip_reported"]} #{data["reported_reason"]}\n"
            output += "**Greynoise**: #{data["greynoise_seen"]}\n"

            if data["greynoise_seen"]
                data["greynoise_data"].each do |result|
                    event << "**Name**: #{result["name"]} **Intention:** #{result["intention"]} **First Seen:** #{result["first_seen"]} **Last Seen:** #{result["last_seen"]} **Category:** #{result["category"]} **Intention:** #{result["intention"]} **Confidence:** #{result["confidence"]}\n"
                end
            end
        else
            output += "You have to supply output\n"
        end
    rescue => e
        output += "Something went wrong here. #{e.to_s}"
    else
        if output.length >= 1998
            output = output[0..1985]
            output += " (truncated)"
        else
            return output
        end
    end

end

# Get Subdomains
bot.command(:getsubs) do |event, domain|
    output = ""
    begin
        data = dnsdumpster.search(domain)
        subdomains = []
        data.each do |item|
            subdomains.push("**" + item["Hostname"].to_s + "** - " + item["IP Address"].to_s + " - " + item["Type"].to_s + " - " + item["Country"].to_s + " - " + item["Netblock Owner"].to_s)
        end

        subdomain_str = subdomains.join("\n")
        output += subdomain_str
    rescue => e
        output += "Something went wrong here. #{e.to_s}"
    else
        if output.length >= 1998
            output = output[0..1985]
            output += " (truncated)"
        else
            return output
        end
    end
end

# Get DNS Dumpster OSINT Map of Domain
bot.command(:getmap) do |event, domain|
    output = ""
    begin
        data = dnsdumpster.search(domain)
        output += "https://dnsdumpster.com/static/map/#{domain}.png"
    rescue => e
        output += "Something went wrong here. #{e.to_s}"
    else
        if output.length >= 1998
            output = output[0..1985]
            output += " (truncated)"
        else
            return output
        end
    end
end

# Get quick links to IP references on censys/shodan
bot.command(:getrefs) do |event, ip|
    event << "**Censys:** https://censys.io/ipv4/#{ip}"
    event << "**Shodan:** https://www.shodan.io/host/#{ip}"
end

# Preform reversewhois on host
bot.command(:revwhois) do |event, *args|
    output = ""
    begin
        output += whois.revwhois(args)
    rescue => e
        output += "Something went wrong here. #{e.to_s}"
    else
        if output.length >= 1998
            output = output[0..1985]
            output += " (truncated)"
        else
            return output
        end
    end
end

# Preform reversewhois on host
bot.command(:shodancount) do |event, *args|
    output = ""
    begin
        count = shodan.count(args.join("+"))["total"]
        output += "The query '#{args.join(" ")}' returned a total host count of **#{count}**\n"
        output += "https://shodan.io/search?query=#{args.join("+")}"
    rescue => e
        output += "Something went wrong here. I can't tell you what."
    else
        if output.length >= 1998
            output = output[0..1985]
            output += " (truncated)"
        else
            return output
        end
    end
end

# PrettyJSON
bot.command(:prettyjson) do |event, json|
    output = ""
    begin
        obj = JSON.parse(json)
        output += '```'
        JSON.pretty_generate(obj).split("\n").each do |line|
            output += "#{line}\n"
        end
        output += '```'
    rescue => e
        output += "Something went wrong here. #{e.to_s}"
    else
        if output.length >= 1998
            output = output[0..1985]
            output += "(truncated) ```"
        else
            return output
        end
    end
end

# Crackhash
bot.command(:crackhash) do |event, passhash|
    output = ""
    begin
        obj = hashcracker.crack(passhash)
        output += "```#{obj}```"
    rescue => e
        error_code = e.to_s.split(" ")[0]
        if error_code == "404"
            output += "Hash not found"
        else
            output += "Something went wrong here. #{e.to_s}"
        end
    else
        if output.length >= 1998
            output = output[0..1985]
            output += "(truncated)"
        else
            return output
        end
    end
end

# Base64 encode
bot.command(:b64encode) do |event, *args|
    output = ""
    begin
        output += Base64.encode64(*args.join(" "))
    rescue => e
        output += "Something went wrong here. #{e.to_s}"
    else
        if output.length >= 1998
            output = output[0..1985]
            output += "(truncated)"
        else
            return output
        end
    end
end

# Base64 decode
bot.command(:b64decode) do |event, base64_text|
    output = ""
    begin
        output += "```" + Base64.decode64(base64_text) + "```"
    rescue => e
        output += "Something went wrong here. #{e.to_s}"
    else
        if output.length >= 1998
            output = output[0..1985]
            output += "(truncated)"
        else
            return output
        end
    end
end

# Impy reverse shells
bot.command(:gimmeshell) do |event, format_opt, ipport|
    output = ""
    begin
        if format_opt == "elf"
            impy = Impy.new("utils/impy/shell.asm")
            ip, port = ipport.split(":")

            res = impy.genPayload(ip, port)
            output += "```#{res}```\n"
        elsif format_opt == "perl"
            impy = Impy.new("utils/impy/shell.asm")
            ip, port = ipport.split(":")

            res = impy.perlPayload(ip, port)
            output += "```#{res}```\n"
        elsif format_opt == "python"
            impy = Impy.new("utils/impy/shell.asm")
            ip, port = ipport.split(":")

            res = impy.pythonPayload(ip, port)
            output += "```#{res}```\n"
        elsif format_opt == "php"
            impy = Impy.new("utils/impy/shell.asm")
            ip, port = ipport.split(":")

            res = impy.phpPayload(ip, port)
            event.channel.send_file res
            res.close()
        else
            output += "Format not found\n"
        end
    rescue => e
        output += "Something went wrong here. #{e.to_s}"
    else
        if output.length >= 1998
            output = output[0..1985]
            output += "(truncated)"
        else
            return output
        end
    end
end

# Lookup Company Linkedin url 
bot.command(:companylinkedin) do |event, *args|
    output = ""
    begin
        url = linkedin.company_page(args.join("+"))
        output += "#{url}\n"
    rescue => e
        output += "Something went wrong here. #{e.to_s}"
    else
        if output.length >= 1998
            output = output[0..1985]
            output += " (truncated)"
        else
            return output
        end
    end
end

# Preform hash functions
bot.command(:hash) do |event, hashtype, *args|
    output = ""
    begin
        data = args.join(" ")
        output += "```#{hashfactory.gen_hash(data, hashtype)}```"
    rescue => e
        output += "Something went wrong here. #{e.to_s}"
    else
        if output.length >= 1998
            output = output[0..1985]
            output += " (truncated)"
        else
            return output
        end
    end
end

# Preform hash functions
bot.command(:hashlookup) do |event, hashtext|
    output = ""
    begin
        algos = hashfactory.identify_hash(hashtext)
        
        if algos.length > 0
            output += "Found #{algos.length} potential hash types.\n"
            output += "```"
            algos.each do | algo |
                output += "#{algo}\n"
            end
            output += "```"
        else
            output += "No hashtypes found."
        end
    rescue => e
        output += "Something went wrong here. #{e.to_s}"
    else
        if output.length >= 1998
            output = output[0..1985]
            output += " (truncated)"
        else
            return output
        end
    end
end

bot.command(:exploits) do |event, *args|
    output = ""
    begin
        query = args.join(" ")
        
        res = exploitdb.search_exploits(query)
        if res.length > 0
            output += "https://www.exploit-db.com/search?q=#{args.join("+")}\n"
            output += "```"
            res.each do |exploit|
                output += "#{exploit["id"]} - #{exploit["title"]} - #{exploit["author"]}\n"
            end
            output += "```"
        else
            output += "No results"
        end
    rescue => e
        output += "Something went wrong here. #{e.to_s}"
    else
        if output.length >= 1995
            output = output[0..1980]
            output += " ```(truncated)"
        else
            return output.chomp
        end
    end
end

bot.command(:shellcodes) do |event, *args|
    output = ""
    begin
        query = args.join(" ")
        
        res = exploitdb.search_shellcodes(query)
        if res.length > 0
            output += "https://www.exploit-db.com/search?q=#{args.join("+")}&type=shellcode\n"
            output += "```"
            res.each do |shellcode|
                output += "#{shellcode["id"]} - #{shellcode["description"]} - #{shellcode["author"]}\n"
            end
            output += "```"
        else
            output += "No results"
        end
    rescue => e
        output += "Something went wrong here. #{e.to_s}"
    else
        if output.length >= 1998
            output = output[0..1985]
            output += "```(truncated)"
        else
            return output
        end
    end
end


bot.command(:getfile) do |event, id|
    output = ""
    begin
        file = exploitdb.get_file(id, path="utils/exploitdb")

        if file != nil 
            output += "`wget https://www.exploit-db.com/raw/#{id}\n`"
            event.channel.send_file file
        else
            output += "ID doesn't exist..."
        end
    rescue => e
        output += "Something went wrong here. #{e.to_s}"
    else
        if output.length >= 1998
            output = output[0..1985]
            output += "(truncated)"
        else
            return output
        end
    end
end

bot.command(:remember, permission_level: 15) do |event, key, *args|
    output = ""

    value = args.join(" ")
    value.gsub!("`", "")
    key.gsub!("`", "")

    output += "Updating key:'#{key}'" if brain.key?(key)
    output += "I remembered '#{key}'" if !brain.key?(key)

    brain[key] = value
    File.open("brain.json", 'w') { |file| file.write(JSON.generate(brain)) }

    output += ""

    begin
        
    rescue => e
        output += "Something went wrong here. #{e.to_s}"
    else
        if output.length >= 1998
            output = output[0..1985]
            output += "(truncated)"
        else
            return output
        end
    end
end

bot.command(:recall, permission_level: 15) do |event, key|
    output = ""

    if key == nil
        output += '```'
        JSON.pretty_generate(brain).split("\n").each do |line|
            output += "#{line}\n"
        end
        output += '```'
    else
        if brain.key?(key)
            output += "I remembered that '#{key}' contained ```#{brain[key]}```"
        else
            output += "Key does not exist\n"
        end
    end
    output += ""

    begin
        
    rescue => e
        output += "Something went wrong here. #{e.to_s}"
    else
        if output.length >= 1998
            output = output[0..1985]
            output += "(truncated)"
        else
            return output
        end
    end
end

bot.command(:forget, permission_level: 15) do |event, key|
    output = ""

    begin
        if key == nil
            output += "Forget what?"
        else
            output += "I forgot '#{key}'\n" if brain.key?(key)
            output += "I didn't forget it, because I never knew it\n" if ! brain.key?(key)
            brain.delete(key) if brain.key?(key)
            File.open("brain.json", 'w') { |file| file.write(JSON.generate(brain)) }

        end
        output += ""        
    rescue => e
        output += "Something went wrong here. #{e.to_s}"
    else
        if output.length >= 1998
            output = output[0..1985]
            output += "(truncated)"
        else
            return output
        end
    end
end

bot.command(:btclookup) do |event, address|
    begin
        output = ""
        address_obj = explorer.get_address_by_base58(address) 

        balance = address_obj.final_balance.to_f / 100000000
        total_received = address_obj.total_received.to_f / 100000000
        total_sent = address_obj.total_sent.to_f / 100000000
        transactions_total = address_obj.transactions.length

        output += "Information for address: **#{address}**"
        output += "```"
        output += "Balance: #{balance} BTC\n"
        output += "Total Received: #{total_received} BTC\n"
        output += "Total Sent: #{total_sent} BTC\n"
        output += "Number of Transactions: #{transactions_total}\n"
        output += "```"
        
    rescue => e
        output += "Something went wrong here. #{e.to_s}"
    else
        if output.length >= 1998
            output = output[0..1985]
            output += "(truncated)"
        else
            return output
        end
    end
end


bot.command(:pwned) do |event, email|
    begin
        output = ""

        res = hibp.getBreaches(email)

        output += "Found **#{res.length}** breaches for **#{email}**\n"
        output += "```"
        res.each do |breach|
            output += "#{breach["Name"]} - #{breach["Domain"]} - #{breach["BreachDate"]}\n"
        end     
        output += "```"
    rescue => e
        output += "No Breaches found."
    else
        if output.length >= 1998
            output = output[0..1985]
            output += "(truncated)"
        else
            return output
        end
    end
end

bot.command(:sploitus) do |event, query|
    begin
        output = ""

        res = sploitus.search_exploits(query)

        output += "Found **#{res.length}** exploits for **#{query}**\n"
        output += "```"
        res.each do |exploit|
            output += "#{exploit["title"]} - #{exploit["score"]} - #{exploit["href"]} - #{exploit["type"]} - #{exploit["published"]}\n"
        end     
        output += "```"
    rescue => e
        output += "No exploits found."
    else
        if output.length >= 1998
            output = output[0..1985]
            output += "(truncated)"
        else
            return output
        end
    end
end

bot.command(:sploitustools) do |event, query|
    begin
        output = ""

        res = sploitus.search_tools(query)

        output += "Found **#{res.length}** tools for **#{query}**\n"
        res.each do |tool|
            output += "**#{tool["title"]}** \n`#{tool["download"]}`\n"
        end     
    rescue => e
        output += "No tools found."
    else
        if output.length >= 1998
            output = output[0..1985]
            output += "(truncated)"
        else
            return output
        end
    end
end

bot.command(:shellmeup, permission_level: 15) do |event, droplet_name|
    begin
        output = ""
        droplet_name.gsub!("`", "")
        if droplet_name != nil

            event.channel.send "Spinning up #{droplet_name}"
            output += shellbox.gimmeShell(droplet_name)

        end
    rescue => e
        output += "Idk bro, probably your fat fingers"
    else
        if output.length >= 1998
            output = output[0..1985]
            output += "(truncated)"
        else
            return output
        end
    end
end

bot.command(:kill, permission_level: 15) do |event, droplet_name|
    begin
        output = ""
        droplet_name.gsub!("`", "")
        if droplet_name != nil
            event.channel.send "Destroying #{droplet_name}"
            output += shellbox.killShell(droplet_name)

        end
    rescue => e
        output += "Idk bro, probably your fat fingers #{e.to_s}"
    else
        if output.length >= 1998
            output = output[0..1985]
            output += "(truncated)"
        else
            return output
        end
    end
end

bot.command(:shells?, permission_level: 15) do |event|
    begin
        output = ""
        shells = shellbox.listShells()
        if shells.length > 0
            output += "**Current Droplets:**"
            output += "```"
            output += ct.genTable(shells)
            output += "```"
        else
            output += "No shells active. Use shellmeup to get some!"
        end
    rescue => e
        output += "Idk bro, probably your fat fingers #{e.to_s}"
    else
        if output.length >= 1998
            output = output[0..1985]
            output += "(truncated)"
        else
            return output
        end
    end
end

bot.command(:records?, permission_level: 15) do |event, domain|
    begin
        output = ""
        if domain == nil
            domain = tokens["domain"]
        end
        records = shellbox.listRecords(domain)
        output += "**Current Records for #{domain}:**"
        output += "```"
        output += JSON.pretty_generate(JSON.parse(records))
        output += "```"
    rescue => e
        output += "Couldn't find anything related to that."
    else
        if output.length >= 1998
            output = output[0..1985]
            output += "(truncated)"
        else
            return output
        end
    end
end


bot.command(:status, permission_level: 15) do |event|
    begin
        output = ""
        res = []

        uptimerobot.getMonitors["monitors"].each do |monitor_data|
            monitor = {
                "name"=>monitor_data["friendly_name"]
            }

            status = ""

            case monitor_data["status"]
            when 0
                status = "Paused"
            when 1
                status = "Not checked yet"
            when 2
                status = "Up"
            when 8
                status = "Seems down"
            when 9
                status = "Down"
            end

            monitor["status"] = status
            res.push(monitor)
        end 

        output += "Server Uptime Status: \n"
        output += "```"
        output += ct.genTable(res)
        output += "```"

    rescue => e
        output += "NO IDEA BUCKO"
    else
        if output.length >= 1998
            output = output[0..1985]
            output += "(truncated)"
        else
            return output
        end
    end
end

# RUN THE BOT - this is important
bot.run
