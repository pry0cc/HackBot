#!/usr/bin/env ruby

require 'discordrb'
require 'json'
require 'mechanize'
require 'creek'
require 'base64'
require 'csv'
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

tokens = {}
perm = {}

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
bot = Discordrb::Commands::CommandBot.new token: tokens["discord_client_token"], prefix: 'yo '

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

# Help menu
bot.command(:help) do |event|
  event << "**yo scanip** *domain*: Get IP info/passive scan with shodan/greynoise"
  event << "**yo getsubs** *domain*: Get Subdomains from DNSDumpster"
  event << "**yo getmap** *domain*: Get Subdomains map from DNSDumpster"
  event << "**yo getrefs** *ip*: Get censys/shodan references"
  event << "**yo revwhois** *name/query*: Get Reversewhois results"
  event << "**yo crackhash** *hash*: Crack hash"
  event << "**yo prettyjson** *json*: Pretty Print JSON"
  event << "**yo b64encode** *text*"
  event << "**yo b64decode** *base64*"
  event << "**yo shodancount** *query*"
  event << "**yo gimmeshell** *127.0.0.1:8080*: Generate a reverse shell with ELF + Base64. Restricted command."
  event << "**yo hashlookup** *somehash*: Identify a hash"
  event << "**yo hash** *sha256* *text*: Identify a hash"
  event << "**yo companylinkedin** *company name*: Try and find company linkedin page."
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
        output += "**Hash:** #{obj["hash"]}\n"
        output += "**Plaintext:** #{obj["plaintext"]}"
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
bot.command(:gimmeshell, permission_level: 10) do |event, ipport|
    output = ""
    begin
        impy = Impy.new("utils/impy/shell.asm")
        ip, port = ipport.split(":")

        res = impy.genPayload(ip, port)
        output += "```#{res}```\n"
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
        if output.length >= 1998
            output = output[0..1985]
            output += " ```(truncated)"
        else
            return output
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

# RUN THE BOT - this is important
bot.run