ActiveRecord::Schema.define(:version => 0) do
  create_table :users, :force => true do |t|
    t.string "login", :limit => 80
    t.string "salt", :limit => 64
    t.string "hashed_password", :limit => 128
    t.string "identity_url", :limit => 64
    t.boolean "verified", :default => false, :null => false
    t.string "security_token", :limit => 128
    t.datetime "token_expiry"
    t.datetime "logged_in_at"
    t.boolean "deleted", :default => false, :null => false
    t.datetime "delete_after"
    t.timestamps
  end
end