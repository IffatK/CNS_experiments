const { transform } = require("../server");

module.exports = async function handler(req, res) {
  if (req.method !== "POST") {
    res.setHeader("Allow", "POST");
    return res.status(405).json({
      error: "Method not allowed"
    });
  }

  try {
    const p = req.body;

    if (!p || !["aes", "des", "2des", "3des"].includes(p.algorithm)) {
      return res.status(400).json({
        error: "Unsupported block cipher."
      });
    }

    if (
      p.mode &&
      (
        !["aes", "des"].includes(p.algorithm) ||
        !["ecb", "cbc", "cfb", "ofb", "ctr"].includes(
          String(p.mode).toLowerCase()
        )
      )
    ) {
      return res.status(400).json({
        error: "Unsupported cipher mode."
      });
    }

    const result = transform({
      ...p,
      detailed: true
    });

    return res.status(200).json(result);

  } catch (error) {
    return res.status(400).json({
      error: error.message
    });
  }
};
