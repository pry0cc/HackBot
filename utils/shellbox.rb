class ShellBox
    def initialize(token, domain="example.com", image="hackbox", region="sfo2", size="s-1vcpu-1gb", email="example@example.com")
        @token = token
        @client = DropletKit::Client.new(access_token: token)
        @image = image
        @region = region
        @size = size
        @agent = Mechanize.new()
        @domain = domain
        @email = email
    end

    def listShells
        shells = []
        droplets = @client.droplets.all
        droplets.each do |droplet|
            shells.push({
                "id"=>droplet.id, 
                "name"=>droplet.name, 
                "ip"=>droplet.public_ip,
                "status"=>droplet.status,
                "size_slug"=>droplet.size_slug
            })
        end
        return shells
    end

    def getRecords(domain)
        data = {}
        headers = {
            "Authorization": "Bearer #{@token}",
            "Content-Type": "application/json"
        }
        @agent.request_headers = headers
        return @agent.get("https://api.digitalocean.com/v2/domains/#{domain}/records").body()
    end

    def addSubdomain(domain, subdomain, ip)
        record = DropletKit::DomainRecord.new(
            type: 'A', 
            name: subdomain,
            data: ip
        )

        return @client.domain_records.create(record, for_domain: domain)
    end

    def removeSubdomain(domain, subdomain)
        records = JSON.parse(listRecords(domain))
        record = records.select {|record| record["name"] == subdomain }
        if record != nil 
            @client.domain_records.delete(for_domain: domain, id: record[0]["id"].to_i)
        end
    end

    def listRecords(domain)
        records = @client.domain_records.all(for_domain: domain)
        return records.to_json
    end

    def gimmeShell(droplet_name)
        output = ""
        droplets = @client.droplets.all
        droplet_exists = false
        droplets.each do |droplet|
            if droplet.name == droplet_name
                droplet_exists = true
            end
        end

        if !droplet_exists
            images = @client.images.all(public:false)
            images.each do |image|
                if image.name == @image
                    user_data = "#cloud-config\n"
                    user_data += "\n"
                    user_data += "runcmd:\n"
                    user_data += "  - /usr/bin/docker run --detach --restart unless-stopped --name nginx-proxy --publish 80:80 --publish 443:443 --volume /etc/nginx/certs --volume /etc/nginx/vhost.d --volume /usr/share/nginx/html --volume /var/run/docker.sock:/tmp/docker.sock:ro jwilder/nginx-proxy\n"
                    user_data += "  - /usr/bin/docker run --detach --restart unless-stopped --name nginx-proxy-letsencrypt --volumes-from nginx-proxy --volume /var/run/docker.sock:/var/run/docker.sock:ro jrcs/letsencrypt-nginx-proxy-companion\n"
                    user_data += "  - /usr/bin/docker run --detach --restart unless-stopped --name web -e \"VIRTUAL_HOST=#{droplet_name}.#{@domain}\" -e \"LETSENCRYPT_HOST=#{droplet_name}.#{@domain}\" -e \"LETSENCRYPT_EMAIL=#{@email}\" -v /home/op/Web:/usr/share/nginx/html nginx\n"
                    user_data += "  - /usr/bin/docker run --detach --restart unless-stopped --expose=80 -p $(ifconfig eth0 | grep \"inet addr:\" | sed 's/:/ /g' | awk '{ print $3 }'):50050:50050 --name cobaltstrike -e \"VIRTUAL_HOST=static.#{droplet_name}.#{@domain}\" -e \"LETSENCRYPT_HOST=static.#{droplet_name}.#{@domain}\" -e \"LETSENCRYPT_EMAIL=#{@email}\" op/cobaltstrike $(ifconfig eth0 | grep \"inet addr:\" | sed 's/:/ /g' | awk '{ print $3 }') OysterArrivalBatteryLethargicJokinglyAcid\n"

                    droplet = DropletKit::Droplet.new(name: droplet_name, region: @region, image: image.id, size: @size, user_data: user_data)
                    @client.droplets.create(droplet)
            
                    while true
                        shells = listShells()
                        res = shells.select {|shell| shell["name"] == droplet_name and shell["status"] == "active"}
                        if res.length > 0
                            shell = res[0]

                            addSubdomain(@domain, droplet_name.downcase, shell["ip"])
                            addSubdomain(@domain, "static." + droplet_name.downcase, shell["ip"])
                            output += "#{shell["name"]} is now active at #{shell["ip"]}\n"
                            output += "```"
                            output += "ssh -p 2266 op@#{shell["ip"]}\n"
                            output += "ssh -p 2266 op@#{droplet_name.downcase}.#{@domain}\n"
                            output += "https://#{droplet_name.downcase}.#{@domain}"
                            output += "```"
                            break
                        end
                    end
                end
            end
        else
            output += "#{droplet_name} already exists."
        end

        return output
    end

    def killShell(droplet_name)
        output = ""
        droplets = @client.droplets.all
        droplets.each do |droplet|
            if droplet.name == droplet_name
                @client.droplets.delete(id: droplet.id)
                removeSubdomain(@domain, droplet_name)
                removeSubdomain(@domain, "static." + droplet_name)
                while true
                    shells = listShells()
                    res = shells.select {|shell| shell["name"] == droplet_name}
                    if res.length == 0
                        output += "#{droplet_name} has been deleted successfully."
                        break;
                    end
                    sleep 1
                end
            end
        end
        return output
    end 
end
