import dotenv from "dotenv";
import express from "express";
import mongoose from "mongoose";
import cors from "cors";
import bodyParser from "body-parser";
import cookieParser from "cookie-parser";
import userRoute from './route/userRoute.js'
import errorHandlerMiddleware from "./middleware/errorHandler.js";
import notFoundMiddleware from "./middleware/not-found.js";

// configure environment variables
dotenv.config();

const app = express();
//middleware
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(bodyParser.json());
app.use(
  cors({
    origin: ["http://localhost:3000", "https://authzzz-app.vercel.app"],
    credentials: true,
  })
);

//Routes
app.use('/api/users', userRoute)

app.get("/", (req, res) => {
  res.send("Home page");
});

//error handling
app.use(notFoundMiddleware);
app.use(errorHandlerMiddleware)

const PORT = process.env.PORT || 5000;

mongoose
  .connect(process.env.MONGO_URL)
  .then(() => {
    app.listen(PORT, () => {
      console.log(`Server running on ${PORT}`);
    });
  })
  .catch((err) => {
    console.log(err);
  });
