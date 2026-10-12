const bcrypt = require("bcrypt");

async function main() {
  const pwd = "Secret123";
  const h1 = await bcrypt.hash(pwd, 10);
  const h2 = await bcrypt.hash(pwd, 10);

  console.log(h1);
  console.log(h2);
  console.log("Урт:", h1.length);
  console.log("Ижил эсэх:", h1 === h2);
  console.log("Зөв нууц үг:", await bcrypt.compare(pwd, h1));
  console.log("Буруу нууц үг:", await bcrypt.compare("secret123", h1));

  for (const cost of [4, 8, 10, 12]) {
    const t = Date.now();
    await bcrypt.hash(pwd, cost);
    console.log("cost", cost, ":", Date.now() - t, "мс");
  }
}

main();