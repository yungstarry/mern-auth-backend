import nodemailer from "nodemailer";
import hbs from "nodemailer-express-handlebars";
import path from "path";

const sendEmail = async (
  subject,
  sent_to,
  sent_from,
  reply_to,
  template,
  name,
  link
) => {
  //create email transporter
  const transporter = nodemailer.createTransport({
    host: process.env.EMAIL_HOST,
    port: 587,
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS,
    },
    tls: {
      rejectUnauthorized: false,
    },
  });

  //views for handlebars
  const handlebarsOptions = {
    viewEngine: {
      extName: ".handlebars",
      partialsDir: path.resolve("./views"),
      defaultLayout: false,
    },
    viewPath: path.resolve("./views"),
    extName: ".handlebars",
  };

  transporter.use("compile", hbs(handlebarsOptions))

  //opti0ns for sending emails
  const options = {
    from: sent_from,
    to: sent_to, // Set the recipient's email address here
    replyTo: reply_to, // Use 'replyTo' to set the reply-to address
    subject: subject,
    template: template,
    context: {
      name,
      link,
    },
  };

  //send email
  transporter.sendMail(options, function (err, info) {
    if (err) {
      console.log(err);
    } else {
      console.log(info);
    }
  });
};
export default sendEmail;
