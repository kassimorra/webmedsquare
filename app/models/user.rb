class User < ActiveRecord::Base
  # Include default devise modules. Others available are:
  # :confirmable, :lockable, :timeoutable and :omniauthable
  devise :database_authenticatable, :registerable,
         :recoverable, :rememberable, :trackable, :validatable,
         :omniauthable, :omniauth_providers => [:linkedin]

	def self.find_for_linkedin_oauth(auth, signed_in_resource=nil)
	  user = User.where(:provider => auth.provider, :uid => auth.uid).first
	  unless user
	    user = User.create(name:auth.extra.raw_info.name,
	                         provider:auth.provider,
	                         uid:auth.uid,
	                         email:auth.info.email,
	                         password:Devise.friendly_token[0,20]
	                         )
	  end
	  user
	end   

	class User < ActiveRecord::Base
	  def self.new_with_session(params, session)
	    super.tap do |user|
	      if data = session["devise.linkedin_data"] && session["devise.linkedin_data"]["extra"]["raw_info"]
	        user.email = data["email-address"] if user.email.blank?
	      end
	    end
	  end
	end 
end
