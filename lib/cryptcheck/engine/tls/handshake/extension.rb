module Cryptcheck::Engine
	module Tls
		class Handshake
			class Extension
				autoload :ServerName, 'cryptcheck/engine/tls/handshake/extension/server_name'
				autoload :SupportedGroups, 'cryptcheck/engine/tls/handshake/extension/supported_groups'

				EXTENSIONS = IdClasses.new(
						ServerName,
						SupportedGroups
				).freeze
				TYPES      = DoubleHash.new({
													0x0000 => :server_name,
													0x0001 => :max_fragment_length,
													0x0002 => :client_certificate_url,
													0x0003 => :trusted_ca_keys,
													0x0004 => :truncated_hmac,
													0x0005 => :status_request,
													0x0006 => :user_mapping,
													0x0007 => :client_authz,
													0x0008 => :server_authz,
													0x0009 => :cert_type,
													0x000A => :supported_groups,
													0x000B => :ec_point_formats,
													0x000C => :srp,
													0x000D => :signature_algorithms,
													0x000E => :use_srtp,
													0x000F => :heartbeat,
													0x0010 => :application_layer_protocol_negotiation,
													0x0011 => :status_request_v2,
													0x0012 => :signed_certificate_timestamp,
													0x0013 => :client_certificate_type,
													0x0014 => :server_certificate_type,
													0x0015 => :padding,
													0x0016 => :encrypt_then_mac,
													0x0017 => :extended_master_secret,
													0x0018 => :token_binding,
													0x0019 => :cached_info,
													0x001A => :tls_lts,
													0x001B => :compress_certificate,
													0x001C => :record_size_limit,
													0x001D => :pwd_protect,
													0x001E => :pwd_clear,
													0x001F => :password_salt,
													0x0023 => :session_ticket,
													0x0029 => :pre_shared_key,
													0x002A => :early_data,
													0x002B => :supported_versions,
													0x002C => :cookie,
													0x002D => :psk_key_exchange_modes,
													0x002F => :certificate_authorities,
													0x0030 => :oid_filters,
													0x0031 => :post_handshake_auth,
													0x0032 => :signature_algorithms_cert,
													0x0033 => :key_share,
													0x0034 => :transparency_info,
													0xFF01 => :renegotiation_info,
											}).freeze

				def self.read(io)
					read   = 0
					r, tmp = io.read_uint16
					id     = TYPES[tmp]
					raise ProtocolError, 'Unknown extension 0x%04X' % tmp unless id
					read      += r
					r, length = io.read_uint16
					read      += r

					clazz        = EXTENSIONS[id]
					r, extension = if clazz
									   clazz.read io
								   else
									   data      = io.read length
									   extension = Extension.new id, data
									   [length, extension]
								   end
					read         += r

					[read, extension]
				end

				def self.write(io, extension)
					io2 = StringIO.new
					extension.write io2

					id      = case extension
							  when Extension
								  extension.id
							  else
								  extension.class::ID
							  end
					id      = TYPES.inverse id
					written = 0
					written += io.write_uint16 id
					written += io.write_data :uint16, io2.string
					written
				end

				def write(io)
					io.write @data
				end

				attr_reader :id, :data

				def initialize(id, data)
					@id   = id
					@data = data
				end
			end
		end
	end
end
