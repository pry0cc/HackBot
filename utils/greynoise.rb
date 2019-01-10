class Greynoise
    def initialize()
        @agent = Mechanize.new()
    end

    def query_ip(ip)
        return JSON.parse(@agent.post("http://api.greynoise.io:8888/v1/query/ip", {"ip"=>ip}).body()) 
    end
end