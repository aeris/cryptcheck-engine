module Cryptcheck::Engine
  module Tls
    class Handshake
      RSpec.describe Certificate do
        let!(:io) { MockIO.new }

        let!(:certificate) {
          der = <<~HEREDOC
            3082032130820209a0030201020208155a92adc2048f90300d06092a864886f7
            0d01010b05003022310b300906035504061302555331133011060355040a130a
            4578616d706c65204341301e170d3138313030353031333831375a170d313931
            3030353031333831375a302b310b3009060355040613025553311c301a060355
            040313136578616d706c652e756c666865696d2e6e657430820122300d06092a
            864886f70d01010105000382010f003082010a0282010100c4803606bae7476b
            089404eca7b691043ff792bc19eefb7d74d7a80d001e7b4b3a4ae60fe8c071fc
            73e7024c0dbcf4bdd11d396bba70464a13e94af83df3e10959547bc955fb412d
            a3765211e1f3dc776caa53376eca3aecbec3aab73b31d56cb6529c8098bcc9e0
            2818e20bf7f8a03afd1704509ece79bd9f39f1ea69ec47972e830fb5ca95de95
            a1e60422d5eebe527954a1e7bf8a86f6466d0d9f16951a4cf7a04692595c1352
            f2549e5afb4ebfd77a37950144e4c026874c653e407d7d23074401f484ffd08f
            7a1fa05210d1f4f0d5ce79702932e2cabe701fdfad6b4bb71101f44bad666a11
            130fe2ee829e4d029dc91cdd6716dbb9061886edc1ba94210203010001a35230
            50300e0603551d0f0101ff0404030205a0301d0603551d250416301406082b06
            01050507030206082b06010505070301301f0603551d23041830168014894fde
            5bcc69e252cf3ea300dfb197b81de1c146300d06092a864886f70d01010b0500
            0382010100591645a69a2e3779e4f6dd271aba1c0bfd6cd75599b5e7c36e533e
            ff3659084324c9e7a504079d39e0d42987ffe3ebdd09c1cf1d914455870b571d
            d19bdf1d24f8bb9a11fe80fd592ba0398cde11e2651e618ce598fa96e5372eef
            3d248afde17463ebbfabb8e4d1ab502a54ec0064e92f7819660d3f27cf209e66
            7fce5ae2e4ac99c7c93818f8b2510722dfed97f32e3e9349d4c66c9ea6396d74
            4462a06b42c6d5ba688eac3a017bddfc8e2cfcad27cb69d3ccdca280414465d3
            ae348ce0f34ab2fb9c618371312b191041641c237f11a5d65c844f0404849938
            712b959ed685bc5c5dd645ed19909473402926dcb40e3469a15941e8e2cca84b
            b6084636a0
          HEREDOC
          OpenSSL::X509::Certificate.new der.from_hex
        }
        let!(:packet) { "000328 000325 #{certificate.to_der.to_hex}" }

        describe '::read' do
          it 'must read record' do
            io.init packet
            record = klass.read nil, io
            expect(io).to be_read 811
            expect(record).to be_a Certificate
            certificates = record.certificates
            expect(certificates.size).to eq 1
            certificate = certificates.first
            expect(certificate).to be_a OpenSSL::X509::Certificate
          end
        end

        describe '#write' do
          it 'must write record' do
            record = klass.new [certificate]
            record.write nil, io
            expect(io).to be_hex_written packet
          end
        end
      end
    end
  end
end
