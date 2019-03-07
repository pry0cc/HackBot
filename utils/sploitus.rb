#!/usr/bin/env ruby

require 'mechanize'
require 'json'

class Sploitus
  def initialize()
    @agent = Mechanize.new()
    @url = "https://sploitus.com/search"
  end

  def search_exploits(query)
    @agent.request_headers = {'content-type'=>'application/json'}
    params = {"type"=>"exploits","sort"=>"default","query"=>query,"title"=>false,"offset"=>0}
    res = @agent.post(@url, JSON.generate(params), 'Content-Type' => 'application/json').body()
    exploits = JSON.parse(res)["exploits"]
    return exploits
  end

  def search_tools(query)
    @agent.request_headers = {'content-type'=>'application/json'}
    params = {"type"=>"tools","sort"=>"default","query"=>query,"title"=>false,"offset"=>0}
    res = @agent.post(@url, JSON.generate(params), 'Content-Type' => 'application/json').body()
    tools = JSON.parse(res)["exploits"]
    return tools
  end
end


