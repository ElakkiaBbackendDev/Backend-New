const mongoose = require("mongoose");
const userSchema=new mongoose.Schema({
    firstName:{type:String,required:true},
    lastName:{type:String,required:true},
    email:{type:String,
        unique:true,
        sparse:true,
        lowercase:true,
        trim:true,
        match:[/^[a-zA-Z0-9._%+-]+@(gmail|outlook|yahoo|thestackly)\.(com|in)$/,"Invalid email"]
    },
    mobile:{type:String,
        unique:true,
        sparse:true,
        trim:true,
        match:[/^[0-9]{10}$/,"Invalid mobile number"]
    },

    alternates: {
        type: [String],
        default: []
    },

    password:{type:String,required:true,select:false},

    passwordHistory:[{ type:String }],

    otp: { type: String },
    otpExpiry: { type: Date },
    
    otpAttempts: { type: Number, default: 0 },

    mobileAttempts:{ type:[String],default:[] },

    newContacts:[
    {
    value: String,
    otp: String,
    otpExpiry: Date
    }
    ]

}, {timestamps:true});

module.exports=mongoose.model("User",userSchema);
