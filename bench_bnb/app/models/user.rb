class User < ApplicationRecord
  validates :username, :password_digest, :session_token, presence: true
  validates :username,  uniqueness: true
  validates :password, length: {minimum: 6, allow_nil: true}

  attr_reader :password

  def password=(pw)
    @password = pw
    self.password_digest = BCrypt::Password.create(pw)
  end

  def is_password?(pw)
    BCrypt::Password.new(self.password_digest).is_password(pw);
  end

  def ensure_session_token
    self.session_token ||= SecureRandom.urlsafe_base64
  end

  def reset_session_token
    self.session_token = SecureRandom.urlsafe_base64
    save!
    self.session_token
  end

  def find_by_credentials(username,password)
    user = User.find_by(username:username)
    user && user.is_password?(password) ? user : nil
  end
end
