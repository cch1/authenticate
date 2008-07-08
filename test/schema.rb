ActiveRecord::Schema.define(:version => 0) do
  create_table :users, :force => true do |t|
    t.string "login", :limit => 80, :null => false
    t.string "salt", :limit => 40, :null => false
    t.string "hashed_password", :limit => 40, :null => false
    t.boolean "verified", :default => false, :null => false
    t.string "security_token", :limit => 40
    t.datetime "token_expiry"
    t.datetime "logged_in_at"
    t.boolean "deleted", :default => false, :null => false
    t.datetime "delete_after"
    t.timestamps
  end
end