const mongoose = require("mongoose");

const uri = "mongodb+srv://kambojlavish3084:Kamb%40543@sangharsh.wx4gq.mongodb.net/feedbacks?retryWrites=true&w=majority&appName=sangharsh";

mongoose.connect(uri, {
    useNewUrlParser: true,
    useUnifiedTopology: true
}).then(() => {
    console.log("✅ Connected to MongoDB successfully!");
}).catch((err) => {
    console.error("❌ MongoDB Connection Error:", err);
});
