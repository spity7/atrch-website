import { Link } from "react-router-dom";
import BlogData from "../../../data/blog.json";
import { containsObject, flatDeep, slugify } from "../../../utils";

const BlogTag = () => {
    const tags = BlogData.map((item) => {
        return item.tags;
    });
    let singleTagArray = flatDeep(tags);
    let allTags = [];
    singleTagArray.forEach((tag) => {
        const obj = {
            title: tag.trim(),
            slug: slugify(tag),
        };
        const objIndex = containsObject(obj, allTags);
        if (objIndex !== -1) {
            allTags[objIndex] = {
                title: tag.trim(),
                slug: slugify(tag),
            };
        } else {
            allTags.push(obj);
        }
    });
    return (
        <div className="widget-tags">
            <span>Tags:</span>
            {allTags.map((tag, i) => {
                return (
                    <Link
                        key={i}
                        to={process.env.PUBLIC_URL + `/tag/${tag.slug}`}
                    >
                        {tag.title}
                        {i !== allTags.length - 1 && ","}
                    </Link>
                );
            })}
        </div>
    );
};

export default BlogTag;
