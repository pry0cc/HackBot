class HashFactory
    def initialize()
        @agent = Mechanize.new()
    end

    def gen_hash(plaintext, hashtype)
        output = ""
        case hashtype
        when 'sha256'
            output += Digest::SHA256.hexdigest plaintext
        when 'sha384'
            output += Digest::SHA384.hexdigest plaintext
        when 'sha512'
            output += Digest::SHA512.hexdigest plaintext
        when 'md5'
            output += Digest::MD5.hexdigest plaintext
        else
            output += "Hashtype not supported."
        end

        return output
    end

    def identify_hash(queryhash)
        res = @agent.post("https://www.onlinehashcrack.com/hash-identification.php", {"hash"=>queryhash, "submit"=>"Submit"}).body()
        potential_algos = []
        Nokogiri::HTML(res).css(".col_two_third")[1].text.split("\n").each do |line|
            if line.include? "-"
                potential_algos.push(line.gsub("\t", "").gsub("- ", ""))
            end
        end

        return potential_algos
    end
end
