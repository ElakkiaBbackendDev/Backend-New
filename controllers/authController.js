const User =require("../models/User");
const bcrypt =require("bcryptjs");
const jwt =require ("jsonwebtoken");
const nodemailer = require("nodemailer");
const sendMail = require("../utils/sendMail");
const crypto=require("crypto");


exports.register = async(req,res) => {
    try{
    const { firstName, lastName, email, mobile, password, confirmPassword } =req.body;

    const errors ={};

    // empty check
    if(!firstName) errors.firstName= "First Name is required";
    if(!lastName) errors.lastName="Last Name is Required"
    if(!email) errors.email= "Email is required";
    if(!mobile) errors.mobile= "Mobile Number is required";
    if(!password) errors.password= "Password cannot be empty";
    if(!confirmPassword) errors.confirmPassword= "Confirm Password cannot be empty";

    if (Object.keys(errors).length>0){
        console.log("Validation Errors:",errors);
        return res.status(400).json({errors});
    }

    //email format check
    const emailPattern = /^[a-zA-Z0-9._%+-]+@(gmail|outlook|yahoo|thestackly)\.(com|in)$/;

    if(!emailPattern.test(email.trim())){
        return res.status(400).json({message: "Enter correct email format \n \t i.e xxx@(gmail|outlook|yahoo|thestackly)\.(com|in)"});
    }

    const formattedEmail = email.trim().toLowerCase();
    //mobile format check

    const mobilePattern=/^[0-9]{10}$/

    if(!mobilePattern.test(mobile.trim())){
        return res.status(400).json({message: "Must enter 10 digit mobile number"});
    }

    // create password with condition
    const passwordPattern = /^(?=.*[A-Z])(?=.*[0-9])(?=.*[!@#$%^&*?]).{8,}$/;

    // check strong password or weak password
    if (!passwordPattern.test(password)){
        return res.status(400).json({
            message:'"Weak Password"---Password must contain: Minimum 8 characters, One Capital letter, One Number and One Special Character'
        });

    }

    // check password with confirm password
    if(password !== confirmPassword ){
        return res.status(400).json({message:" Passwords do not Match"});
    }

    // check existing user
    const existingUser =await User.findOne({ $or:[{email:formattedEmail},{mobile}],
    });

    if (existingUser) {
      return res.status(400).json({ message: "User already exists" });
    }

    // password hashing
    const hashedPassword= await bcrypt.hash(password,10);

    // create new user
    const newUser = new User({
        firstName,
        lastName,
        email:formattedEmail,
        mobile,
        password:hashedPassword
    });

    // save user
    await newUser.save();

    res.status(201).json({message:"User Registered Successfully"});
} catch (error) {
    console.log(error)
    res.status(500).json({ message: "Server error"});
}

};


    const isEmail=(input) =>{
        return /^[a-zA-Z0-9._%+-]+@(gmail|outlook|yahoo|thestackly)\.(com|in)$/.test(input);
    };
    const isMobile=(input) =>{
        return /^[0-9]{10}$/.test(input);
    };

exports.login = async(req,res) =>{

    try{
    const {emailormobile,password}=req.body;

    if (!emailormobile || !password) {
         return res.status(400).json({ message: "Email/Mobile and Password are required" });
    }

    const input = emailormobile.trim();

        // ❌ Format check
        if (!isEmail(input) && !isMobile(input)) {
            return res.status(400).json({
                message: "Invalid Email or Mobile format"
            });
        }

        // 🔍 Build query
        let query;
        if (isEmail(input)) {
            query = { email: input };
        } else {
            query = { mobile: input };
        }

        // 🔍 Find user
        const user = await User.findOne(query).select("+password");

    if(!user){
        return res.status(400).json({message:"User not found"});
    }

    const isMatch =await bcrypt.compare(password,user.password);
    if(!isMatch){
        return res.status(400).json({ message:"Incorrect Password. If you Forgot it? click Forgot Password"});
     }

    res.status(200).json({message:" Login Successful" });
    }catch (error) {
        console.error("Login Error:", error);
        res.status(500).json({message:"Server error" });
      }
};

exports.forgotPassword = async (req, res) => {
    try {
        const { input, isChange, primaryUser } = req.body;

        if (!input) {
            return res.status(400).json({
                message: "Email or Mobile required"
            });
        }

        const inputVal = input.toLowerCase().trim();

        // email and mobile validation
        const isEmail = /^[a-zA-Z0-9._%+-]+@(gmail|outlook|yahoo|thestackly)\.(com|in)$/.test(inputVal);
        const isMobile = /^[0-9]{10}$/.test(inputVal);

        if (!isEmail && !isMobile) {
            return res.status(400).json({
                message: "Enter valid Email or Mobile"
            });
        }

        // Change mode (add alternate)
        if (isChange) {

            if (!primaryUser) {
                return res.status(400).json({
                    message: "Primary user required"
                });
            }

            // find primary user
            let user = await User.findOne({
                $or: [
                    { email: primaryUser },
                    { mobile: primaryUser }
                ]
            });

            if (!user) {
                return res.status(400).json({
                    message: "Primary user not found"
                });
            }

            // cannot use primary
            if (inputVal === user.email || inputVal === user.mobile) {
                return res.status(400).json({
                    message: "Cannot use primary credentials"
                });
            }

            // user alternates
            let userList = user.alternates || [];

            // duplicate for same user
            if (userList.includes(inputVal)) {
                return res.status(400).json({
                    message: "Already added as alternate"
                });
            }

            // limit check
            if (userList.length >= 2) {
                return res.status(400).json({
                    message: "Only 2 alternates allowed",
                    existing: userList
                });
            }

            // global duplicate check
            const existingAlt = await User.findOne({
                alternates: inputVal
            });

            if (existingAlt) {
                return res.status(400).json({
                    message: "Already used as alternate"
                });
            }

            // save alternate
            userList.push(inputVal);
            user.alternates = userList;

            await user.save();

            return res.json({
                message: "Alternate added successfully",
                alternates: userList
            });
        }

        // normal forgot password

        let user = null;

        if (isEmail) {
            user = await User.findOne({ email: inputVal });
        } else {
            user = await User.findOne({ mobile: inputVal });
        }

        // check alternates
        if (!user) {
            user = await User.findOne({
                alternates: inputVal
            });
        }

        if (!user) {
            return res.status(400).json({
                message: "Email or Mobile not registered"
            });
        }

        // generate otp
        const newOtp = Math.floor(1000 + Math.random() * 9000).toString();

        user.otp = newOtp;
        user.otpExpiry = Date.now() + 1 * 60 * 1000;
        user.otpAttempts = 0;

        await user.save();

        console.log("OTP:", newOtp);

        return res.json({
            message: "OTP sent successfully",
            otp: newOtp // remove in production
        });

    } catch (error) {
        console.error(error);
        return res.status(500).json({
            message: "Server error"
        });
    }
};

// Verify OTP by Email
exports.verifyOtpByEmail = async (req, res) => {
    try {
        const { email, otp } = req.body;

        // Find user
        const user = await User.findOne({ email });
        if (!user) return res.status(400).json({ message: "User not found" });

        const now = Date.now();
       
        // Check max attempts
        if (user.otpAttempts >= 3) {
            await user.save();
            return res.status(400).json({ 
                message: "Maximum OTP attempts exceeded. Please Resend OTP" 
            });
        }

        // Check OTP
        if (user.otp !== otp) {
            user.otpAttempts += 1;
            await user.save();
            return res.status(400).json({
                message: "Invalid OTP"
            });
        }

        // Check OTP expiry
        if (user.otpExpiry < now) {
            await user.save();
            return res.status(400).json({ 
                message: "OTP expired.Please Resend OTP"
             });
        }

        // OTP verified → generate reset token
        const resetToken = crypto.randomBytes(32).toString("hex");
        user.resetToken = resetToken;
        user.resetTokenExpiry = now + 5 * 60 * 1000; // 5 mins
        user.otpAttempts = 0; // reset attempts after success
        await user.save();

        return res.json({ message: "OTP verified Successfully", resetToken });

    } catch (err) {
        console.error(err);
        return res.status(500).json({ message: "Server error" });
    }
};

exports.verifyOtpByMobile = async (req, res) => {
    try {
        const { mobile, otp } = req.body;

        // Find user by mobile
        const user = await User.findOne({ mobile });
        if (!user) {
            return res.status(400).json({ message: "User not found" });
        }

        const now = Date.now();

        // otp expired- reset attempts
        if (user.otpExpiry < now ){
                user.otpAttempts =0;
                await user.save();
                return res.status(400).json({
                    message:"OTP Expired. Please Resend OTP"
                });
        }

        // Check max attempts
        if (user.otpAttempts >= 3) {
            return res.status(400).json({
                message: "Maximum OTP attempts exceeded. Please resend OTP"
            });
        }

        // Check OTP match
        if (user.otp !== otp) {
            user.otpAttempts += 1;
            await user.save();

            return res.status(400).json({
                message: "Invalid OTP"
            });
        }

        // OTP verified → generate reset token
        const resetToken = crypto.randomBytes(32).toString("hex");

        user.resetToken = resetToken;
        user.resetTokenExpiry = now + 5 * 60 * 1000; // 5 mins
        user.otpAttempts = 0; // reset attempts
        user.otp = null; // optional: clear OTP after success

        await user.save();

        return res.json({
            message: "OTP verified successfully",
            resetToken
        });

    } catch (err) {
        console.error(err);
        return res.status(500).json({ message: "Server error" });
    }
};

exports.resetPassword = async (req, res) => {
    try {
        const { input, newPassword, confirmPassword } = req.body;
        if(!input){
            return res.status(400).json({
                message:"Email or Mobile required"
            });
        }

        const isEmail= /^[a-zA-Z0-9._%+-]+@(gmail|outlook|yahoo)\.(com|in)$/.test(input);
        const isMobile= /^[0-9]{10}$/.test(input);

        let user;
        
        if(isEmail){
            user = await User.findOne({ email:input }).select("+password");
        }else if (isMobile){
            user = await User.findOne({ mobile:input }).select("+password");
        }

        if (!user) {
            return res.status(400).json({ message: "User not found" });
        }

        if (!newPassword || !confirmPassword) {
            return res.status(400).json({ message: "Password fields required" });
        }

        if (newPassword !== confirmPassword) {
            return res.status(400).json({ message: "Passwords do not match" });
        }

        // Combine current + last 3 passwords
        const allPasswords = [user.password, ...(user.passwordHistory || [])];

        // Check new password against last 3
        for (let oldPass of allPasswords) {
            const isMatch = await bcrypt.compare(newPassword, oldPass);
            if (isMatch) {
                return res.status(400).json({
                    message: "You cannot reuse last 3 passwords"
                });
            }
        }

        // Hash new password
        const hashedPassword = await bcrypt.hash(newPassword, 10);

        // Update password history (keep only last 3)
        user.passwordHistory = [
            user.password,
            ...(user.passwordHistory || [])
        ].slice(0, 3);

        // Save new password
        user.password = hashedPassword;
        
        // Clear OTP after use
        user.otp = null;
        user.otpExpiry = null;

        await user.save();  

        res.json({
            message: "Password reset successfully",
            redirectUrl: "/login.html"
        });

        } catch (error) {
        return res.status(500).json({ message: "Server error" });
    }
};