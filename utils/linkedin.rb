class Linkedin
    def initialize()
        @agent = Mechanize.new()
        @agent.user_agent_alias = 'Mac Safari'
    end

    def company_page(query)
        url = "https://www.bing.com/search?q=site%3Alinkedin.com%2Fcompany%2F+%2#{query.gsub(" ", "+")}%22&qs=n&form=QBRE"
        linkedin_url = Nokogiri::HTML(@agent.get(url).body()).at_css(".b_algo").at_css("a")["href"]
        return linkedin_url
    end
end