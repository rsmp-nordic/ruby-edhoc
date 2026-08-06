module Edhoc
  # Raw OSCORE material and direction-specific IDs exported from EDHOC.
  class OscoreContext
    attr_reader :master_secret, :master_salt, :sender_id, :recipient_id

    def initialize(master_secret:, master_salt:, sender_id:, recipient_id:)
      @master_secret = master_secret
      @master_salt = master_salt
      @sender_id = sender_id
      @recipient_id = recipient_id
    end

    def destroy!
      [@master_secret, @master_salt].each do |secret|
        secret.replace("\0" * secret.bytesize)
        secret.clear
      end
      self
    end
  end
end
