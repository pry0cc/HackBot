#!/usr/bin/env ruby

require 'discordrb'
require 'json'
require 'mechanize'
require 'creek'
require './utils/dnsdumpster.rb'
require './utils/greynoise.rb'
require './utils/littleshodan.rb'
require './utils/reversewhois.rb'
require './utils/ipinfo.rb'

tokens = {}

if File.file?("tokens.json")
    begin
        tokens = JSON.parse(File.open("tokens.json").read())
    rescue
        puts "tokens.json is either invalid or empty!"
    end
else
    puts "tokens.json does not exist."
end

ipinfo = IPInfo.new(tokens["shodan"])
dnsdumpster = DNSDumpster.new()
whois = ReverseWhois.new()
bot = Discordrb::Commands::CommandBot.new token: tokens["discord_client_token"], prefix: 'yo '

# Help menu
bot.command(:help) do |event|
  event << "yo scanip: Get IP info/passive scan with shodan/greynoise"
  event << "yo getsubs: Get Subdomains from DNSDumpster"
  event << "yo getmap: Get Subdomains map from DNSDumpster"
end

# Get OSINT on IP
bot.command(:scanip) do |event, ip|
    output = ""
    begin
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

bot.run
