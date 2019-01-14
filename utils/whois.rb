class ReverseWhois
    def initialize()
        @agent = Mechanize.new()
        @agent.user_agent = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36"
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
