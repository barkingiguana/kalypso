# frozen_string_literal: true

require "net/http"
require "json"
require "uri"

# Kalypso Ruby SDK — request SSL certificates from a Kalypso CA server.
#
# Usage:
#   client = Kalypso::Client.new("http://kalypso:8200")
#   cert = client.issue("myapp.local", "*.myapp.local")
#   cert.save("cert.pem", "key.pem")
#
module Kalypso
  class Certificate
    attr_reader :certificate_pem, :private_key_pem, :ca_certificate_pem,
                :domains, :not_after

    def initialize(data)
      @certificate_pem    = data["certificate"]
      @private_key_pem    = data["private_key"]
      @ca_certificate_pem = data["ca_certificate"]
      @domains            = data["domains"]
      @not_after          = data["not_after"]
    end

    def save(cert_path, key_path)
      File.write(cert_path, @certificate_pem)
      File.write(key_path, @private_key_pem)
    end

    def save_ca(ca_path)
      File.write(ca_path, @ca_certificate_pem)
    end

    def save_fullchain(path)
      File.write(path, @certificate_pem + @ca_certificate_pem)
    end
  end

  class Client
    def initialize(base_url = "http://localhost:8200")
      @base_url = base_url.chomp("/")
    end

    def health
      get("/health")
    end

    def ca_certificate
      get("/ca.pem")["certificate"]
    end

    def issue(*domains, hours: 24, ip_addresses: nil)
      body = { domains: domains, hours: hours }
      body[:ip_addresses] = ip_addresses if ip_addresses

      data = post("/certificates", body)
      Certificate.new(data)
    end

    private

    def get(path)
      uri = URI("#{@base_url}#{path}")
      response = Net::HTTP.get_response(uri)
      JSON.parse(response.body)
    end

    def post(path, body)
      uri = URI("#{@base_url}#{path}")
      http = Net::HTTP.new(uri.host, uri.port)
      request = Net::HTTP::Post.new(uri.path, "Content-Type" => "application/json")
      request.body = body.to_json
      response = http.request(request)
      JSON.parse(response.body)
    end
  end
end
