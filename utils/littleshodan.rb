class LittleShodan
    def initialize(apikey)
        @apikey = apikey
        @agent = Mechanize.new()
    end

    def host(ip)
        return JSON.parse(@agent.get("https://api.shodan.io/shodan/host/#{ip}?key=#{@apikey}").body())
    end

    def count(query)
        return JSON.parse(@agent.get("https://api.shodan.io/shodan/host/count?query=#{query}&key=#{@apikey}").body())
    end
end