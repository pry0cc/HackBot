#!/usr/bin/env ruby

require 'nokogiri'
require 'mechanize'
require 'creek'

class DNSDumpster

    def initialize()
        @agent = Mechanize.new()
        @dnsdumpster_url = "https://dnsdumpster.com/"
    end

    def get_csrf_token()
        req = @agent.get(@dnsdumpster_url).body()

        # Extract token from form
        csrftoken = Nokogiri::HTML(req).at_css("input")["value"]
        return csrftoken
    end

    def add_csrftoken_cookie(token)
        cookie = Mechanize::Cookie.new("csrftoken", token)
        cookie.domain = "dnsdumpster.com"
        cookie.path = "/"
        @agent.cookie_jar.add(cookie)
    end

    def xlsx_to_array(xlsx_url)
        if xlsx_url != ""
            creek = Creek::Book.new xlsx_url, remote: true
        end

        sheet = creek.sheets[0]
        masterkey = sheet.rows.first
        data = []
        sheet.rows.each do |row|
            row_data = {}
            if row != masterkey
                row.each do |key, value|
                    identifier = masterkey[key[0] + "1"]
                    if value != nil
                        row_data[identifier] = value
                    end
                end
            end

            if row_data.length > 0
                data.push(row_data)
            end
        end

        return data
    end

    def xlsx_url_from_page(page)
        xlsx_url = ""

        page.css("a").each do |a|
            if a["href"] != nil
                if a["href"].include? "xlsx"
                    xlsx_url = a["href"]
                end
            end
        end

        return xlsx_url
    end

    def search(domain)
        token = get_csrf_token()
        add_csrftoken_cookie(token)

        data = {'csrfmiddlewaretoken'=> token, 'targetip' => domain}
        req = @agent.post(@dnsdumpster_url, data)
        page = Nokogiri::HTML(req.body())
        domain_map = "https://dnsdumpster.com" + page.css("img").attr("src")

        xlsx_url = xlsx_url_from_page(page)
        data = xlsx_to_array(xlsx_url)

        return data
    end

end

# dnsdumpster = DNSDumpster.new()
# puts dnsdumpster.search("0x00sec.org")
