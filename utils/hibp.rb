class HaveIBeenPwned
    def initialize()
        @agent = Mechanize.new()
    end

    def getBreaches(email)
        res = JSON.parse(@agent.get("https://haveibeenpwned.com/api/v2/breachedaccount/#{email}").body())
        return res
    end
end