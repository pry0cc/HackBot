class IPInfo
    def initialize(shodan_apikey)
        @greynoise = Greynoise.new()
        @shodan = LittleShodan.new(shodan_apikey)
        @agent = Mechanize.new()
    end

    def scan(ip)
        data = {}
        begin
            result = @shodan.host(ip)
            copy_list = ["ports"]
        rescue
            copy_list = []
        end

        data["ip"] = ip
        
        copy_list.each do |param|
            data[param] = result[param]
        end

        ipinfo = JSON.parse(@agent.get("https://ipinfo.io/#{ip}").body())

        ["city", "region", "loc", "country", "org"].each do |param|
            data[param] = ipinfo[param]
        end

        page = Nokogiri::HTML(@agent.get("https://www.abuseipdb.com/check/#{ip}").body())

        status = page.css(".well").css("h3").text
        
        if status.include? "was found in our database!"
            status = true
            status_reason = page.css(".well").at_css("p").text.gsub(": ?", "")
            
        elsif status.include? "was not found in our database"
            status = false
        end

        data["ip_reported"] = status
        data["reported_reason"] = status_reason if status

        greynoise_data = @greynoise.query_ip(ip)

        if greynoise_data["status"] == "ok"
            records = []
            greynoise_data["records"].each do |record|
                records.push({
                    "name" => record["name"],
                    "intention" => record["intention"],
                    "first_seen" => record["first_seen"],
                    "category" => record["category"],
                    "confidence" => record["confidence"]
                })
                data["greynoise_data"] = records
                data["greynoise_seen"] = true
            end
        else
            data["greynoise_seen"] = false
        end

        if data["greynoise_seen"] == false && data["ip_reported"] == false
            data["clean"] = true
        else
            data["clean"] = false
        end

        return data
    end
end