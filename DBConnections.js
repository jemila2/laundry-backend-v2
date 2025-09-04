// // DBConnections.js
// const mongoose = require('mongoose');

// const connectDB = async () => {
//   try {
//     // Clean up the MongoDB URI
//     let mongoURI = process.env.MONGODB_URI;
    
//     // Remove any port numbers from mongodb+srv URI
//     if (mongoURI.includes('mongodb+srv://') && mongoURI.includes(':')) {
//       // Remove port number from mongodb+srv URI
//       mongoURI = mongoURI.replace(/:(\d+)/, '');
//     }
    
//     // Fix common Atlas URI issues
//     if (mongoURI.includes('laundrycluster.xxbljuz.mongodb.net/Laundry?retryWrites=true&w=majoritylaundrycluster')) {
//       mongoURI = mongoURI.replace('laundrycluster.xxbljuz.mongodb.net/Laundry?retryWrites=true&w=majoritylaundrycluster', 
//         'laundrycluster.xxbljuz.mongodb.net/Laundry?retryWrites=true&w=majority');
//     }
    
//     console.log(`Attempting MongoDB connection to: ${mongoURI.replace(/:[^:]*@/, ':********@')}`);
    
//     const conn = await mongoose.connect(mongoURI, {
//       serverSelectionTimeoutMS: 10000,
//       socketTimeoutMS: 45000,
//     });
    
//     console.log(`✅ MongoDB Connected Successfully: ${conn.connection.host}`);
//     return true;
//   } catch (error) {
//     console.error(`❌ MongoDB Connection Failed: ${error.message}`);
//     return false;
//   }
// };

// module.exports = connectDB;


// Correct MongoDB Atlas connection
const mongoose = require('mongoose');

const connectDB = async () => {
  try {
    const conn = await mongoose.connect(
      'mongodb+srv://jemilaabubakar9_db_user:gU3K9qKZlRbBfyIX@cluster-name.xxbljuz.mongodb.net/Laundry_services?retryWrites=true&w=majority',
      {
        useNewUrlParser: true,
        useUnifiedTopology: true,
      }
    );
    console.log(`✅ MongoDB Connected: ${conn.connection.host}`);
  } catch (error) {
    console.error('❌ MongoDB Connection Failed:', error.message);
    process.exit(1);
  }
};

module.exports = connectDB;