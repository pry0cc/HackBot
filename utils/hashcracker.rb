class HashCracker
    def initialize()
        @agent = Mechanize.new
    end

    def crack(hash)
        return hashtoolkit(hash)
    end

    def hashtoolkit(hash)
        res = @agent.get("http://hashtoolkit.com/reverse-hash?hash=#{hash}").body()
        return Nokogiri::HTML(res).at_css(".res-text").css("span")[0].text
    end
end
