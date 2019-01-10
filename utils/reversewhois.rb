class ReverseWhois
    def initialize()
        @agent = Mechanize.new()
    end

    def revwhois(args)
        res = ""
        url = "https://viewdns.info/reversewhois/?q=#{args.join("+")}"
        res += url + "\n"
        Nokogiri::HTML(@agent.get(url).body()).css("table")[3].css("tr").each do |tr|
            td_array = tr.css("td")
            res += "**#{td_array[0].text}** #{td_array[1].text} **#{td_array[2].text}**\n"
        end
        return res
    end
end