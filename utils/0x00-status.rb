class 0x00Status
    def initialize()
        @agent = Mechanize.new()
    end

    def getStatus()
        return JSON.parse(@agent.get("https://status.0x00sec.org/api/status-page/WQzXxI2xB/1?sort=1/").body())
    end
end