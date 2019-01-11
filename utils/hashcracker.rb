class HashCracker
    def initialize()
        @agent = Mechanize.new
    end

    def crack(hash)
        plaintext = leakz(hash)
        res = {
            "hash"=>hash,
            "plaintext"=>plaintext
        }

        return res
    end

    def leakz(hash)
        res = JSON.parse(@agent.get("https://lea.kz/api/hash/#{hash}").body())
        plaintext = res["password"]
        return plaintext
    end
end