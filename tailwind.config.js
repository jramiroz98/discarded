/** @type {import('tailwindcss').Config} */
module.exports = {
  content: ["./templates/**/*.{templ,html,js}", "./components/**/*.{templ,html,js}"],
  theme: {
    extend: {
      backgroundImage: {
        'sd-jar': "url('/static/images/home/sd-jar.avif')"
      }
    },
  },
  plugins: [],
}

